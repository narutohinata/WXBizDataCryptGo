package WXBizDataCrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

type WXBizDataCrypt struct {
	AppId string
	SessionKey string
}

type WxData struct {
	NickName string `json:"nickName"`
	Gender int `json:"gender"`
	Language string `json:"language"`
	City string `json:"city"`
	Province string `json:"province"`
	Country string `json:"country"`
	AvatarUrl string `json:"avatarUrl"`
	UnionId string `json:"union_id"`
	WaterMark WaterMark `json:"watermark"`
}

type WaterMark struct {
	Timestamp int `json:"timestamp"`
	AppId string `json:"appid"`
}

type WXBizDataCryptError struct {
	message string
}

func (e WXBizDataCryptError) Error() string{
	return fmt.Sprintf("has a error: %v", e.message)
}

func NewWXBizDataCrypt(appId, sessionKey string) *WXBizDataCrypt {
	return &WXBizDataCrypt{
		appId,
		sessionKey,
	}
}

func (crpyt *WXBizDataCrypt) DecryptData(encryptedData string, iv string) (*WxData, error){
	sessionKey, _ := base64.StdEncoding.DecodeString(crpyt.SessionKey)
	_iv, _ := base64.StdEncoding.DecodeString(iv)
	_encryptedData, _ := base64.StdEncoding.DecodeString(encryptedData)

	block, err := aes.NewCipher(sessionKey)
	if err != nil {
		panic(err)
	}
	mode := cipher.NewCBCDecrypter(block, _iv)
	mode.CryptBlocks(_encryptedData, _encryptedData)
	fmt.Println(string(PKCS7UnPadding(_encryptedData)))

	data := WxData{}

	err = json.Unmarshal(PKCS7UnPadding(_encryptedData), &data)
	if err != nil {
		panic(err)
	}

	if data.WaterMark.AppId != crpyt.AppId {
		return nil, WXBizDataCryptError{"Invalid Buffer"}
	}


	return &data, nil
	
}

func PKCS7UnPadding(origData []byte) []byte {
	length := len(origData)
	unPadding := int(origData[length - 1])
	return origData[:(length - unPadding)]
}
