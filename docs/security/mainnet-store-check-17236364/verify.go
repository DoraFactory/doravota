//go:build ignore

// Standalone evidence verifier: run with the 0.4.4 module dependencies.
package main
import("encoding/json";"encoding/hex";"fmt";"os";"bytes";"crypto/sha256";"path/filepath";"strings"; ics23 "github.com/confio/ics23/go")
type Response struct{Result struct{Response struct{Code int `json:"code"`; Height string `json:"height"`; Value []byte `json:"value"`; ProofOps struct{Ops []struct{Type string `json:"type"`;Key []byte `json:"key"`;Data []byte `json:"data"`} `json:"ops"`} `json:"proofOps"`} `json:"response"`} `json:"result"`}
func main(){
 b,e:=os.ReadFile("/tmp/vota-store-check/anchor-block.json");must(e)
 var block struct{Result struct{Block struct{Header struct{AppHash string `json:"app_hash"`} `json:"header"`} `json:"block"`} `json:"result"`};must(json.Unmarshal(b,&block));anchor,e:=hex.DecodeString(block.Result.Block.Header.AppHash);must(e)
 names:=[]string{"fee-locked","cap-index"}; paths,e:=filepath.Glob("/tmp/vota-store-check/cap-owner-*.json");must(e);for _,p:=range paths{names=append(names,strings.TrimSuffix(filepath.Base(p),".json"))}; for _,name:=range names{
 b,e=os.ReadFile("/tmp/vota-store-check/"+name+".json");must(e);var j Response;must(json.Unmarshal(b,&j));r:=j.Result.Response
 var storeRoot []byte
 for _,op:=range r.ProofOps.Ops{if op.Type!="ics23:simple"{continue};var p ics23.CommitmentProof;must(p.Unmarshal(op.Data));ex:=p.GetExist();if ex==nil{panic("no store membership proof")};if !ics23.VerifyMembership(ics23.TendermintSpec,anchor,&p,op.Key,ex.Value){panic("invalid multistore proof")};storeRoot=ex.Value;empty:=sha256.Sum256(nil);fmt.Printf("%s height=%s store=%s root=%X anchored=true empty=%v\n",name,r.Height,op.Key,storeRoot,bytes.Equal(storeRoot,empty[:]))}
 if strings.HasPrefix(name,"cap-"){for _,op:=range r.ProofOps.Ops{if op.Type!="ics23:iavl"{continue};var p ics23.CommitmentProof;must(p.Unmarshal(op.Data));if !ics23.VerifyMembership(ics23.IavlSpec,storeRoot,&p,op.Key,r.Value){panic("invalid capability index proof")};fmt.Println(name+" membership verified")}}
 }
}
func must(e error){if e!=nil{panic(e)}}
