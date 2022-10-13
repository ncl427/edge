/*
	Copyright NetFoundry Inc.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

	https://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/

package model

import (
	"fmt"
	"math/big"
	"os"
	"log"
	"regexp"
	"reflect"
	"container/list"
	"encoding/json"
	"strconv"
	"strings"


	"github.com/lucsky/cuid"
	"github.com/openziti/edge/controller/apierror"
	"github.com/openziti/edge/controller/persistence"
	fabricApiError "github.com/openziti/fabric/controller/apierror"
	"github.com/openziti/fabric/controller/models"
	"github.com/openziti/foundation/v2/errorz"
	"github.com/openziti/foundation/v2/stringz"
	"github.com/openziti/storage/ast"
	"github.com/openziti/storage/boltz"
	"github.com/joho/godotenv"
	"go.etcd.io/bbolt"
	"github.com/chenzhijie/go-web3"
	//"github.com/chenzhijie/go-web3/types"
	"github.com/ethereum/go-ethereum/common"
	"time"
)

func NewSessionManager(env Env) *SessionManager {
	manager := &SessionManager{
		baseEntityManager: newBaseEntityManager(env, env.GetStores().Session),
	}
	manager.impl = manager
	return manager
}

type SessionManager struct {
	baseEntityManager
}

type SessionToken struct {
	TokenId      *big.Int `json:"tokenId"`
	TokenType    string   `json:"tokenType"`
	Valid        bool     `json:"valid"`    
}

func (self *SessionManager) newModelEntity() edgeEntity {
	return &Session{}
}

type SessionPostureResult struct {
	Passed           bool
	Failure          *PostureSessionRequestFailure
	PassingPolicyIds []string
	Cause            *fabricApiError.GenericCauseError
}

type MetaData struct {
	PolicyID int `json:"policyId"`
	Exp      int `json:"exp"`
}

//For checking if an Identity has a valid address
func IsValidAddress(v string) bool {
    re := regexp.MustCompile("^0x[0-9a-fA-F]{40}$")
    return re.MatchString(v)
}

func (self *SessionManager) EvaluatePostureForService(identityId, apiSessionId, sessionType, serviceId, serviceName string) *SessionPostureResult {

	failureByPostureCheckId := map[string]*PostureCheckFailure{} //cache individual check status
	validPosture := false
	hasMatchingPolicies := false

	policyPostureCheckMap := self.GetEnv().GetManagers().EdgeService.GetPolicyPostureChecks(identityId, serviceId)

	failedPolicies := map[string][]*PostureCheckFailure{}
	failedPoliciesIdToName := map[string]string{}

	var failedPolicyIds []string
	var successPolicyIds []string


	for policyId, policyPostureCheck := range policyPostureCheckMap {

		if policyPostureCheck.PolicyType.String() != sessionType {
			continue
		}
		hasMatchingPolicies = true
		var failedChecks []*PostureCheckFailure

		for _, postureCheck := range policyPostureCheck.PostureChecks {

			found := false

			if _, found = failureByPostureCheckId[postureCheck.Id]; !found {
				_, failureByPostureCheckId[postureCheck.Id] = self.GetEnv().GetManagers().PostureResponse.Evaluate(identityId, apiSessionId, postureCheck)
			}

			if failureByPostureCheckId[postureCheck.Id] != nil {
				failedChecks = append(failedChecks, failureByPostureCheckId[postureCheck.Id])
			}
		}

			//Checks that only valid address Ids have session tokens


		if len(failedChecks) == 0 {
			validPosture = true
			// Added for verification of session tokens
			if IsValidAddress(identityId) {
				polycyTokens := self.checkSessionToken(identityId)
				extractedPoli := strings.Split(policyId, "_")
				result := contains(polycyTokens, extractedPoli[0])
				if result {
					successPolicyIds = append(successPolicyIds, policyId)
				}else{
					validPosture = false
					failedPolicyIds = append(failedPolicyIds, policyId)
				}
			}else{
				successPolicyIds = append(successPolicyIds, policyId)
			}
		} else {
			//save for error output
			failedPolicies[policyId] = failedChecks
			failedPoliciesIdToName[policyId] = policyPostureCheck.PolicyName
			failedPolicyIds = append(failedPolicyIds, policyId)
		}
	}

	//fmt.Printf("\nThe service policies that are valid and active are:  ", successPolicyIds)

	if hasMatchingPolicies && !validPosture {
		failureMap := map[string]interface{}{}

		sessionFailure := &PostureSessionRequestFailure{
			When:           time.Now(),
			ServiceId:      serviceId,
			ServiceName:    serviceName,
			ApiSessionId:   apiSessionId,
			SessionType:    sessionType,
			PolicyFailures: []*PosturePolicyFailure{},
		}

		for policyId, failures := range failedPolicies {
			policyFailure := &PosturePolicyFailure{
				PolicyId:   policyId,
				PolicyName: failedPoliciesIdToName[policyId],
				Checks:     failures,
			}

			var outFailures []interface{}

			for _, failure := range failures {
				outFailures = append(outFailures, failure.ToClientErrorData())
			}
			failureMap[policyId] = outFailures

			sessionFailure.PolicyFailures = append(sessionFailure.PolicyFailures, policyFailure)
		}

		cause := &fabricApiError.GenericCauseError{
			Message: fmt.Sprintf("Failed to pass posture checks for service policies: %v", failedPolicyIds),
			DataMap: failureMap,
		}

		return &SessionPostureResult{
			Passed:           false,
			Cause:            cause,
			PassingPolicyIds: nil,
			Failure:          sessionFailure,
		}
	}

	return &SessionPostureResult{
		Passed:           true,
		Cause:            nil,
		PassingPolicyIds: successPolicyIds,
		Failure:          nil,
	}
}

//For verifying if session tokens are valid with respect of a policy
func contains(s []string, e string) bool {
    for _, a := range s {
		fmt.Println("\n Comparing data: ",a,e)
        if a == e {
            return true
        }
    }
    return false
}
//For handling the env variables for the Blockchain
func goDotEnvVariable(key string) string {

	// load .env file
	err := godotenv.Load(".env")
  
	if err != nil {
	  log.Fatalf("Error loading .env file")
	}
  
	return os.Getenv(key)
  }

func (self *SessionManager) checkSessionToken(identityId string) []string {
	fmt.Printf("\n\nVerifying session tokens for %v\n", identityId)

	var sessionTokensPolicyIds []string

	// We need to clean this part. Should be called only once. Verify where!!
	rpcProvider := goDotEnvVariable("RPCURL")
	sessionTokenAddress := goDotEnvVariable("TOKENADDRESS")
	sessionTokenABI := goDotEnvVariable("ABI")

	fmt.Printf("godotenv : %s = %s \n", "RPCURL", rpcProvider)
	
	web3, err := web3.NewWeb3(rpcProvider)

	if err != nil {
		panic(err)
	}
	blockNumber, err := web3.Eth.GetBlockNumber()
	if err != nil {
		panic(err)
	}
	contract, err := web3.Eth.NewContract(sessionTokenABI, sessionTokenAddress)
	if err != nil {
		panic(err)
	}
	//Checking Contract Address
	fmt.Println("Contract address: ", contract.Address())

	// Checking the Blockcnumber
	fmt.Println("Current block number: ", blockNumber)

	// Checking the Total Supply of Tokens
	totalSupply, err := contract.Call("totalSupply")
	if err != nil {
		panic(err)
	}

	fmt.Printf("Total supply %v\n", totalSupply)

	//To convert to a correct address
    idAddress := common.HexToAddress(identityId)

	//var myTokens []SessionToken

	ownedTokens, err := contract.Call("getOwnedNfts", idAddress)
	if err != nil {
		panic(err)
	}
	fmt.Printf("The session tokens for this Identity are %v \n", ownedTokens)
	
	//myTokens = ownedTokens.([]SessionToken)
	l := iterateToken(ownedTokens)

	

	for e := l.Front(); e != nil; e = e.Next() {
		fmt.Println("TokenId is", e.Value) // print out the elements
		metadata, err := contract.Call("tokenURI", e.Value)
		if err != nil {
			panic(err)
		}
		
		fmt.Printf("The metadata for this token is %v \n", metadata)
		// Declared an empty interface
	    result := metadata.(string)
		var result2 MetaData 
		//metaMap := make(map[string]interface{})

		e := json.Unmarshal([]byte(result), &result2)

		if e != nil {
				panic(e)
		}

		//for key, value := range metaMap {
	//			fmt.Println("index : ", key, " value : ", value)
	//	}
	    fmt.Println("The policyId of this token is: ", result2.PolicyID)

		sessionTokensPolicyIds = append(sessionTokensPolicyIds, strconv.Itoa(result2.PolicyID))



	}
	return sessionTokensPolicyIds




	
}

func iterateToken(t interface{}) *list.List {
	
   var tokenId *big.Int
   l := list.New()
	switch reflect.TypeOf(t).Kind() {
    case reflect.Slice:
        s := reflect.ValueOf(t)

        for i := 0; i < s.Len(); i++ {
			//id := reflect.ValueOf(s.Index(i)).Elem().FieldByName("TokenId")
			//fmt.Println("TokenId", id)
            //fmt.Println(s.Index(i))
			conreteSession:= s.Index(i).Interface()
			//fmt.Println(conreteSession)

			v := reflect.ValueOf(conreteSession).FieldByName("TokenId")
			fmt.Println("fields: ", reflect.ValueOf(conreteSession).NumField())
			tokenId = v.Interface().(*big.Int)
        
			
			//fmt.Println("TokenId is", v, tokenId)
			l.PushFront(tokenId)

			//Start working in here for getting the TokenURI()
			// VERIFY TEH PROVIDER TOKEN

			//blogPost := conreteSession.(*SessionPostureResult)
			//fmt.Println(blogPost)
        }
		
    }

	return l

	




}

func (self *SessionManager) Create(entity *Session) (string, error) {
	entity.Id = cuid.New() //use cuids which are longer than shortids but are monotonic




	apiSession, err := self.GetEnv().GetManagers().ApiSession.Read(entity.ApiSessionId)
	if err != nil {
		return "", err
	}
	if apiSession == nil {
		return "", errorz.NewFieldError("api session not found", "ApiSessionId", entity.ApiSessionId)
	}

	service, err := self.GetEnv().GetManagers().EdgeService.ReadForIdentity(entity.ServiceId, apiSession.IdentityId, nil)
	if err != nil {
		return "", err
	}

	if entity.Type == "" {
		entity.Type = persistence.SessionTypeDial
	}

	if persistence.SessionTypeDial == entity.Type && !stringz.Contains(service.Permissions, persistence.PolicyTypeDialName) {
		return "", errorz.NewFieldError("service not found", "ServiceId", entity.ServiceId)
	}

	if persistence.SessionTypeBind == entity.Type && !stringz.Contains(service.Permissions, persistence.PolicyTypeBindName) {
		return "", errorz.NewFieldError("service not found", "ServiceId", entity.ServiceId)
	}

	policyResult := self.EvaluatePostureForService(apiSession.IdentityId, apiSession.Id, entity.Type, service.Id, service.Name)

	if !policyResult.Passed {
		self.env.GetManagers().PostureResponse.postureCache.AddSessionRequestFailure(apiSession.IdentityId, policyResult.Failure)
		return "", apierror.NewInvalidPosture(policyResult.Cause)
	}

	
	

	maxRows := 1
	result, err := self.GetEnv().GetManagers().EdgeRouter.ListForIdentityAndService(apiSession.IdentityId, entity.ServiceId, &maxRows)
	if err != nil {
		return "", err
	}
	if result.Count < 1 {
		return "", apierror.NewNoEdgeRoutersAvailable()
	}

	entity.ServicePolicies = policyResult.PassingPolicyIds
	fmt.Println("\nI am creating a session for", apiSession.IdentityId, " and", service.Name)

	return self.createEntity(entity)
}

func (self *SessionManager) ReadByToken(token string) (*Session, error) {
	modelSession := &Session{}
	tokenIndex := self.env.GetStores().Session.GetTokenIndex()
	if err := self.readEntityWithIndex("token", []byte(token), tokenIndex, modelSession); err != nil {
		return nil, err
	}
	return modelSession, nil
}

func (self *SessionManager) ReadForIdentity(id string, identityId string) (*Session, error) {
	identity, err := self.GetEnv().GetManagers().Identity.Read(identityId)

	if err != nil {
		return nil, err
	}
	if identity.IsAdmin {
		return self.Read(id)
	}

	query := fmt.Sprintf(`id = "%v" and apiSession.identity = "%v"`, id, identityId)
	result, err := self.Query(query)
	if err != nil {
		return nil, err
	}
	if len(result.Sessions) == 0 {
		return nil, boltz.NewNotFoundError(self.GetStore().GetSingularEntityType(), "id", id)
	}
	return result.Sessions[0], nil
}

func (self *SessionManager) Read(id string) (*Session, error) {
	entity := &Session{}
	if err := self.readEntity(id, entity); err != nil {
		return nil, err
	}
	return entity, nil
}

func (self *SessionManager) readInTx(tx *bbolt.Tx, id string) (*Session, error) {
	entity := &Session{}
	if err := self.readEntityInTx(tx, id, entity); err != nil {
		return nil, err
	}
	return entity, nil
}

func (self *SessionManager) DeleteForIdentity(id, identityId string) error {
	session, err := self.ReadForIdentity(id, identityId)
	if err != nil {
		return err
	}
	if session == nil {
		return boltz.NewNotFoundError(self.GetStore().GetSingularEntityType(), "id", id)
	}
	return self.deleteEntity(id)
}

func (self *SessionManager) Delete(id string) error {
	return self.deleteEntity(id)
}

func (self *SessionManager) PublicQueryForIdentity(sessionIdentity *Identity, query ast.Query) (*SessionListResult, error) {
	if sessionIdentity.IsAdmin {
		return self.querySessions(query)
	}
	identityFilterString := fmt.Sprintf(`apiSession.identity = "%v"`, sessionIdentity.Id)
	identityFilter, err := ast.Parse(self.Store, identityFilterString)
	if err != nil {
		return nil, err
	}
	query.SetPredicate(ast.NewAndExprNode(query.GetPredicate(), identityFilter))
	return self.querySessions(query)
}

func (self *SessionManager) ReadSessionCerts(sessionId string) ([]*SessionCert, error) {
	var result []*SessionCert
	err := self.GetDb().View(func(tx *bbolt.Tx) error {
		var err error
		certs, err := self.GetEnv().GetStores().Session.LoadCerts(tx, sessionId)
		if err != nil {
			return err
		}
		for _, cert := range certs {
			modelSessionCert := &SessionCert{}
			if err = modelSessionCert.FillFrom(self, tx, cert); err != nil {
				return err
			}
			result = append(result, modelSessionCert)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (self *SessionManager) Query(query string) (*SessionListResult, error) {
	result := &SessionListResult{manager: self}
	err := self.ListWithHandler(query, result.collect)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (self *SessionManager) querySessions(query ast.Query) (*SessionListResult, error) {
	result := &SessionListResult{manager: self}
	err := self.PreparedListWithHandler(query, result.collect)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (self *SessionManager) ListSessionsForEdgeRouter(edgeRouterId string) (*SessionListResult, error) {
	result := &SessionListResult{manager: self}
	query := fmt.Sprintf(`anyOf(apiSession.identity.edgeRouterPolicies.routers) = "%v" and `+
		`anyOf(service.serviceEdgeRouterPolicies.routers) = "%v"`, edgeRouterId, edgeRouterId)
	err := self.ListWithHandler(query, result.collect)
	if err != nil {
		return nil, err
	}
	return result, nil
}

type SessionListResult struct {
	manager  *SessionManager
	Sessions []*Session
	models.QueryMetaData
}

func (result *SessionListResult) collect(tx *bbolt.Tx, ids []string, queryMetaData *models.QueryMetaData) error {
	result.QueryMetaData = *queryMetaData
	for _, key := range ids {
		entity, err := result.manager.readInTx(tx, key)
		if err != nil {
			return err
		}
		result.Sessions = append(result.Sessions, entity)
	}
	return nil
}
