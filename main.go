package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/s3/s3manager"
	"github.com/golang-jwt/jwt"
)

func main() {
	keyID := flag.String("key-id", "", "Key ID for apple store")
	issuer := flag.String("issuer", "", "Issuer for apple store")
	keyFile := flag.String("key-file", "", "Private key file in p8 format")
	file := flag.String("file", "", "File to notarize")
	print := flag.Bool("print-jwt", false, "Print the JWT and exit")
	submitted := flag.String("submission-id", "", "Use submission ID to check status & logs of uploaded file")
	tries := flag.Int("tries", 100, "Status check retries (every 15 seconds)")
	flag.Parse()

	if *keyID == "" || *issuer == "" || *keyFile == "" {
		flag.Usage()
		return
	}

	token, err := createJWT(*keyFile, *keyID, *issuer, 30*time.Minute)
	if err != nil {
		fmt.Printf("Failed to create JWT: %v\n", err)
		os.Exit(1)
	}
	if *print {
		fmt.Println(token)
		return
	}

	if *file == "" && *submitted == "" {
		fmt.Println("Provide --file or --submission-id flag")
		os.Exit(2)
	}

	if *submitted != "" {
		printStatusAndLogs(*submitted, token)
		return
	}

	prefix := "" //time.Now().Format(time.RFC3339)+ "-"
	submRes, err := submit(token, *file, prefix)
	if err != nil {
		fmt.Printf("Failed to submit notarization: %v\n", err)
	}
	fmt.Printf("Submission ID: %v\n", submRes.Data.ID)

	err = awsUpload(*file, submRes)
	if err != nil {
		fmt.Printf("Failed to upload file for notarization: %v\n", err)
		os.Exit(3)
	}

	for i := 0; i < *tries; i++ {
		var status StatusResult
		raw, err := doRequest(
			"GET", "https://appstoreconnect.apple.com/notary/v2/submissions/"+submRes.Data.ID,
			token, nil, &status)
		if err != nil {
			fmt.Printf("Failed to check submission status: %v\n", err)
			os.Exit(3)
		}
		if status.Data.Attributes.Status == "" {
			fmt.Printf("Sumbit status empty; raw response: %+v\n", raw)
			os.Exit(3)
		}
		fmt.Printf("Sumbit status: %v\n", status.Data.Attributes.Status)
		if status.Data.Attributes.Status == "Invalid" {
			break
		}
		if status.Data.Attributes.Status == "Accepted" {
			logs, err := getLogs(submRes.Data.ID, token)
			if err != nil {
				fmt.Printf("Failed to get submission logs: %v\n", err)
			} else {
				fmt.Println(logs)
			}
			fmt.Println("Notarization successfully complete.")
			return
		}
		time.Sleep(15 * time.Second)
	}
	fmt.Println("Notarization failed to complete.")
	os.Exit(4)
}

type SubmissonResult struct {
	Data struct {
		ID         string `json:"id"`
		Attributes struct {
			AWSAccessKeyID     string `json:"awsAccessKeyId"`
			AWSSecretAccessKey string `json:"awsSecretAccessKey"`
			AWSSessionToken    string `json:"awsSessionToken"`
			Bucket             string `json:"bucket"`
			Object             string `json:"object"`
		} `json:"attributes"`
	} `json:"data"`
}

type StatusResult struct {
	Data struct {
		Attributes struct {
			Status string `json:"status"`
			Name   string `json:"name"`
		} `json:"attributes"`
	} `json:"data"`
}

type LogResult struct {
	Data struct {
		Attributes struct {
			DeveloperLogURL string `json:"developerLogUrl"`
		} `json:"attributes"`
	} `json:"data"`
}

func submit(jwt, file, prefix string) (sr SubmissonResult, err error) {
	sha, err := getSHA256(file)
	if err != nil {
		return sr, fmt.Errorf("failed to calculate SHA256 of file to notarize: %v", err)
	}

	body := []byte(fmt.Sprintf(`{
	"submissionName": "%v%v",
	"sha256": "%v"
}`, prefix, file, sha))
	fmt.Println(string(body))

	_, err = doRequest(
		"POST", "https://appstoreconnect.apple.com/notary/v2/submissions",
		jwt, body, &sr)
	return sr, err
}

func printStatusAndLogs(id, jwt string) {
	var status StatusResult
	_, err := doRequest(
		"GET", "https://appstoreconnect.apple.com/notary/v2/submissions/"+id,
		jwt, nil, &status)
	if err != nil {
		fmt.Printf("Failed to check submission status: %v\n", err)
		os.Exit(5)
	}
	fmt.Printf("Status: %v\n", status.Data.Attributes.Status)
	fmt.Printf("File:   %v\n", status.Data.Attributes.Name)

	logs, err := getLogs(id, jwt)
	if err != nil {
		fmt.Printf("Failed to download submission logs: %v\n", err)
		os.Exit(5)
	}
	fmt.Printf("Logs:\n%v\n", logs)
}

func getLogs(id, jwt string) (string, error) {
	var resp LogResult
	raw, err := doRequest(
		"GET", "https://appstoreconnect.apple.com/notary/v2/submissions/"+id+"/logs",
		jwt, nil, &resp)
	if err != nil {
		return raw, err
	}
	if resp.Data.Attributes.DeveloperLogURL == "" {
		return raw, fmt.Errorf("returned logs URL is empty")
	}
	respLogs, err := http.Get(resp.Data.Attributes.DeveloperLogURL)
	if err != nil {
		return "", fmt.Errorf("failed to download logs from S3: %v", err)
	}
	defer respLogs.Body.Close()
	logs, err := io.ReadAll(respLogs.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read AWS response: %v", err)
	}
	return string(logs), err
}

func doRequest(method, url, jwt string, body []byte, response any) (raw string, err error) {
	client := http.Client{}
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %v", err)
	}
	if method == "POST" {
		req.Header.Add("Content-type", "application/json")
	}
	req.Header.Add("Authorization", "Bearer "+jwt)
	resp, err := client.Do(req)
	if err != nil {
		status := 0
		if resp != nil {
			status = resp.StatusCode
		}
		return "", fmt.Errorf("request failed, status %v: %v", status, err)
	}
	defer resp.Body.Close()

	res, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %v", err)
	}

	if response != nil {
		err = json.Unmarshal(res, response)
		if err != nil {
			return string(res), fmt.Errorf("failed to unmarshal response: %v", err)
		}
	}
	return string(res), nil
}

func getSHA256(file string) (string, error) {
	h := sha256.New()
	f, err := os.Open(file)
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()

	_, err = io.Copy(h, f)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%x", h.Sum(nil)), nil
}

func awsUpload(file string, sr SubmissonResult) error {
	fmt.Println("Uplading file to AWS...")
	sess, err := session.NewSession(&aws.Config{
		Region: aws.String("us-west-2"),
		Credentials: credentials.NewStaticCredentials(
			sr.Data.Attributes.AWSAccessKeyID,
			sr.Data.Attributes.AWSSecretAccessKey,
			sr.Data.Attributes.AWSSessionToken,
		),
	})
	if err != nil {
		return fmt.Errorf("failed to initialize AWS session: %w", err)
	}

	uploader := s3manager.NewUploader(sess, func(u *s3manager.Uploader) {
		u.PartSize = 5 * 1024 * 1024
		u.Concurrency = 4
	})

	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("failed to open file: %w", err)
	}
	defer f.Close()

	_, err = uploader.Upload(&s3manager.UploadInput{
		Bucket: aws.String(sr.Data.Attributes.Bucket),
		Key:    aws.String(sr.Data.Attributes.Object),
		Body:   f,
	})
	if err != nil {
		return fmt.Errorf("failed to upload file: %w", err)
	}

	fmt.Println("File uploaded to AWS")
	return nil
}

func createJWT(keyFile, kid, iss string, validFor time.Duration) (string, error) {
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		return "", err
	}

	pkey, err := parsePKCS8PrivateKeyFromPEM(keyBytes)
	if err != nil {
		return "", err
	}

	now := time.Now().UTC().Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"iss": iss,
		"iat": now,
		"exp": now + int64(validFor.Seconds()),
		"aud": "appstoreconnect-v1",
	})
	token.Header["kid"] = kid

	return token.SignedString(pkey)
}

func parsePKCS8PrivateKeyFromPEM(key []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, jwt.ErrKeyMustBePEMEncoded
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	pkey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, jwt.ErrNotECPrivateKey
	}

	return pkey, nil
}
