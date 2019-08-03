/*
 * Copyright 2018 The openwallet Authors
 * This file is part of the openwallet library.
 *
 * The openwallet library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * The openwallet library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 */

package horizen

import (
	"encoding/hex"
	"github.com/assetsadapterstore/horizen-adapter/horizen_addrdec"
	"testing"
)

func TestAddressDecoder_AddressEncode(t *testing.T) {
	horizen_addrdec.Default.IsTestNet = false

	p2pk, _ := hex.DecodeString("28daa861e86d49694937c3ee6e637d50e8343e4b")
	p2pkAddr, _ := horizen_addrdec.Default.AddressEncode(p2pk)
	t.Logf("p2pkAddr: %s", p2pkAddr)

	p2sh, _ := hex.DecodeString("df23c5eaba30b4d95798c5d5d0e2ecc2a3dc4ff2")
	p2shAddr, _ := horizen_addrdec.Default.AddressEncode(p2sh, horizen_addrdec.ZEN_mainnetAddressP2SH)
	t.Logf("p2shAddr: %s", p2shAddr)
}

func TestAddressDecoder_AddressDecode(t *testing.T) {

	horizen_addrdec.Default.IsTestNet = false

	p2pkAddr := "znUovxhrE91tep6D7YtgSc3XJZoYQLVDwVn"
	p2pkHash, _ := horizen_addrdec.Default.AddressDecode(p2pkAddr)
	t.Logf("p2pkHash: %s", hex.EncodeToString(p2pkHash))

	p2shAddr := "zszpcLB6C5B8QvfDbF2dYWXsrpac5DL9WRk"

	p2shHash, _ := horizen_addrdec.Default.AddressDecode(p2shAddr, horizen_addrdec.ZEN_mainnetAddressP2SH)
	t.Logf("p2shHash: %s", hex.EncodeToString(p2shHash))
}

func TestAddressDecoder_ScriptPubKeyToBech32Address(t *testing.T) {

	scriptPubKey, _ := hex.DecodeString("002079db247b3da5d5e33e036005911b9341a8d136768a001e9f7b86c5211315e3e1")

	addr, err := tw.Decoder.ScriptPubKeyToBech32Address(scriptPubKey)
	if err != nil {
		t.Errorf("ScriptPubKeyToBech32Address failed unexpected error: %v\n", err)
		return
	}
	t.Logf("addr: %s", addr)


	t.Logf("addr: %s", addr)
}