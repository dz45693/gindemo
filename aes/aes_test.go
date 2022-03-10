package aes

import (
	"encoding/json"
	"testing"
	"time"
)

func TestEncrypt(t *testing.T) {
	md5key := GetAesKey("gavin12345678")

	mapData := make(map[string]interface{}, 0)
	mapData["name"] = "gavin"
	mapData["age"] = 25
	mapData["update_time"] = time.Now().Unix()
	mapData["folder"] = "test"
	jsonByte, _ := json.Marshal(mapData)
	jsonStr := string(jsonByte)
	//////////////////////
	str, err := GcmEncrypt(md5key, jsonStr)
	if err != nil {
		t.Log(err)
	}
	t.Log(str)

}

func TestDecrypt(t *testing.T) {
	md5key := GetAesKey("gavin12345678")
	str := "fvOU6R_c8iTgImJ29LkM0-1FvXdTgVCiMYjhJRG3ePz1KziVUV_fx-6XgDjEfpp_juOEt_vWwNMreP0P_QmTiuHeNeymC1WRRQCWW-eJUHNi4CNl1IMJvGJxEO0jcg=="
	/////////////////////////
	jsonStr, err := GcmDecrypt(md5key, str)
	if err != nil {
		t.Log(err)
	}
	t.Log(jsonStr)
}
