// Copyright 2025 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package utils

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"

	"github.com/andybalholm/brotli"
)

func CompressAndBase64Encode(input []byte) (string, error) {
	var buf bytes.Buffer
	writer := brotli.NewWriter(&buf)
	_, err := writer.Write(input)
	if err != nil {
		return "", err
	}
	writer.Close()
	return base64.StdEncoding.EncodeToString(buf.Bytes()), nil
}

func DecompressAndBase64Decode(input string) ([]byte, error) {
	decoded, err := base64.StdEncoding.DecodeString(input)
	if err != nil {
		return nil, err
	}
	reader := brotli.NewReader(bytes.NewReader(decoded))
	decompressed, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}

	return decompressed, nil
}
