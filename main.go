package main

import (
	"bufio"
	"cmp"
	b64 "encoding/base64"
	hex "encoding/hex"
	"fmt"
	"math"
	"os"
	"slices"
	"sort"
	"strings"
)

func ex1() {
	s := "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	newS := b64.StdEncoding.EncodeToString(b)
	fmt.Printf("Result is: %s\n", newS)
}

func ex2() {
	s := "1c0111001f010100061a024b53535009181c"
	s_bytes, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	key := "686974207468652062756c6c277320657965"
	key_bytes, err := hex.DecodeString(key)
	if err != nil {
		panic(err)
	}
	expected := "746865206b696420646f6e277420706c6179"
	result := make([]byte, 0)
	for i := 0; i < len(s_bytes); i++ {
		result = append(result, s_bytes[i]^key_bytes[i])
	}
	stringResult := hex.EncodeToString(result)
	fmt.Println(stringResult == expected)
}

func computeScore(s string) float64 {
	// 65 a 122 incluso
	score := 0.0
	for _, c := range s {
		if (int(c) != 32 && int(c) < 65) || int(c) > 122 {
			score++
		}
	}
	return math.Round(score/float64(len(s))*10) / 10
}

type decryptionResult struct {
	score     float64
	plaintext string
	key       int
}

func xor(input []byte, key byte) []byte {
	result := make([]byte, 0)
	for j := 0; j < len(input); j++ {
		result = append(result, input[j]^key)
	}
	return result
}

func ex3() {
	encrypted := "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
	encBytes, err := hex.DecodeString(encrypted)
	if err != nil {
		panic(err)
	}
	// scores := make(map[int]decryptionResult)
	scores := make([]decryptionResult, 0)
	for i := 0; i < 256; i++ {
		stringResult := string(xor(encBytes, byte(i)))
		scores = append(scores, decryptionResult{plaintext: stringResult, score: computeScore(stringResult), key: i})
	}
	slices.SortFunc(scores,
		func(a, b decryptionResult) int {
			return cmp.Compare(a.score, b.score)
		})
	for i := 0; i < 10; i++ {
		fmt.Println(scores[i])
	}
}

type possibleResult struct {
	score     float64
	plaintext string
	key       int
	src       string
}

func Insert(sa []possibleResult, el possibleResult) []possibleResult {
	saLen := len(sa)
	i := sort.Search(len(sa),
		func(i int) bool {
			return sa[i].score > el.score
		})
	fmt.Printf("top10 len: %d | insert index: %d\n", saLen, i)
	if saLen < 10 {
		sa = append(sa, possibleResult{})
		copy(sa[i+1:], sa[i:])
	} else if i <= saLen-2 {
		copy(sa[i+1:], sa[i:saLen-2])
	}
	sa[i] = el
	return sa
}

func ex4() {
	f, err := os.Open("4.txt")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	top10 := make([]possibleResult, 0, 10)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		s := scanner.Text()
		b, err := hex.DecodeString(s)
		if err != nil {
			panic(err)
		}
		for i := 0; i < 256; i++ {
			stringResult := string(xor(b, byte(i)))
			score := computeScore(stringResult)
			top10Len := len(top10)
			if top10Len < 10 || top10[top10Len-1].score > score {
				top10 = Insert(top10, possibleResult{score: score, plaintext: stringResult, key: i, src: s})
			}
		}
	}
	for _, e := range top10 {
		fmt.Println(e)
	}

}
func hammingDistance(b1, b2 []byte) int {
	// should have same len
	count := 0
	for i := 0; i < len(b1); i++ {
		for j := 1; j <= 128; j *= 2 {
			// res := (b1[i] ^ b2[i]) & byte(j)
			// fmt.Printf("j: %d, res: %d\n", j, res)
			if (b1[i]^b2[i])&byte(j) != 0 {
				count++
			}
		}
	}
	return count
}

func ex5p1() {
	s1 := "this is a test"
	s2 := "wokka wokka!!!"
	// s1 := "a"
	// s2 := "b"
	fmt.Printf("a: %d, b: %d\n", int('a'), int('b'))
	expectedDistance := 37
	b1 := []byte(s1)
	b2 := []byte(s2)
	calculateDistance := hammingDistance(b1, b2)
	if calculateDistance == expectedDistance {
		fmt.Printf("distances match!\n")
	} else {
		fmt.Printf("distances don't match. Expected %d, received %d\n", expectedDistance, calculateDistance)
	}
}

func cycleXor(encr, key []byte) []byte {
	result := make([]byte, len(encr))
	for i := 0; i < len(encr); i++ {
		result[i] = encr[i] ^ key[i%len(key)]
	}
	return result
}

func InsertKeySize(sa []keySize, el keySize, maxLen int) []keySize {
	saLen := len(sa)
	i := sort.Search(saLen, func(i int) bool {
		return sa[i].distance > el.distance
	})
	if saLen < maxLen {
		sa = append(sa, keySize{})
		copy(sa[i+1:], sa[i:])
	} else if i <= saLen-2 {
		copy(sa[i+1:], sa[i:saLen-2])
	}
	sa[i] = el
	return sa
}

type keySize struct {
	distance float64
	size     int
}

func ex5() {
	content, err := os.ReadFile("6.txt")
	if err != nil {
		panic(err)
	}
	content = []byte(strings.ReplaceAll(string(content), "\n", ""))
	_, err = b64.StdEncoding.Decode(content, content)
	if err != nil {
		panic(err)
	}
	elCount := 5
	bestKeySizes := make([]keySize, 0, elCount)
	for keysize := 2; keysize <= 40; keysize++ {
		normalizedDistance := 0.0
		samplesNumber := 4
		for i := 0; i < samplesNumber; i++ {
			normalizedDistance += float64(hammingDistance(content[i*keysize:(i+1)*keysize], content[(i+1)*keysize:(i+2)*keysize]) / keysize)
		}
		normalizedDistance /= float64(samplesNumber)
		if len(bestKeySizes) < elCount || bestKeySizes[elCount-1].distance > normalizedDistance {
			bestKeySizes = InsertKeySize(bestKeySizes, keySize{size: keysize, distance: normalizedDistance}, elCount)
		}
	}
	for _, el := range bestKeySizes {
		fmt.Printf("size: %d norm_dist: %f\n", el.size, el.distance)
	}
	f, err := os.OpenFile("decrypted.txt", os.O_RDWR|os.O_CREATE, 0755)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	for _, keysize := range bestKeySizes {
		key := make([]byte, keysize.size)
		for k := 0; k < keysize.size; k++ {
			block := make([]byte, 0)
			for i := 0; i+k < len(content); i += keysize.size {
				block = append(block, content[i+k])
			}
			// fmt.Println("block", block)
			bestScore := -1.0
			for i := 0; i < 256; i++ {
				stringResult := string(xor(block, byte(i)))
				score := computeScore(stringResult)
				if bestScore == -1.0 || score < bestScore {
					bestScore = score
					key[k] = byte(i)
				}
			}
			fmt.Printf("score for index %d was %f\n", k, bestScore)
		}
		fmt.Println("the key is", key)
		f.WriteString("\nNEW KEYSIZES\n\n")
		f.WriteString(string(cycleXor(content, key)))
		// fmt.Println(string(cycleXor(content, key)))

	}
}

func ex6() {
	content, err := os.ReadFile("7.txt")
	if err != nil {
		panic(err)
	}
	_, err = b64.StdEncoding.Decode(content, content)
	if err != nil {
		panic(err)
	}
	key := "YELLOW SUBMARINE"
	for i := 0; i+16 < len(content); i += 16 {
		plaintext := cycleXor(content[i:i+16], []byte(key))
		fmt.Println(string(plaintext))
	}
}

func main() {
	ex6()
	// for _, el := range []byte("YELLOW SUBMARINE") {
	// 	fmt.Println(el)
	// }

}
