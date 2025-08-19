use crate::error::ContractError;
use crate::msg::{
    CheckPolicyResponse, ExecuteMsg, GetCountResponse, InstantiateMsg, MigrateMsg, QueryMsg, WhitelistResponse,
};
use crate::state::{State, STATE, WHITELIST};
use cosmwasm_std::{
    entry_point, to_binary, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
};
use serde_json::Value;
use cw2::set_contract_version;

// version info for migration info
const CONTRACT_NAME: &str = "crates.io:counter";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> Result<Response, ContractError> {
    let state = State {
        count: msg.initial_count,
        owner: info.sender.clone(),
    };
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    STATE.save(deps.storage, &state)?;

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("owner", info.sender)
        .add_attribute("count", msg.initial_count.to_string()))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn execute(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> Result<Response, ContractError> {
    match msg {
        ExecuteMsg::Increment { amount } => execute_increment(deps, info, amount),
        ExecuteMsg::Decrement {} => execute_decrement(deps),
        ExecuteMsg::Reset { count } => execute_reset(deps, info, count),
        ExecuteMsg::AddToWhitelist { address } => execute_add_to_whitelist(deps, info, address),
        ExecuteMsg::RemoveFromWhitelist { address } => {
            execute_remove_from_whitelist(deps, info, address)
        }
    }
}

pub fn execute_increment(deps: DepsMut, info: MessageInfo, amount: i32) -> Result<Response, ContractError> {
    // check if the user is whitelisted
    let is_whitelisted = WHITELIST
        .may_load(deps.storage, &info.sender)?
        .unwrap_or(false);
    if !is_whitelisted {
        return Err(ContractError::NotWhitelisted {});
    }

    STATE.update(deps.storage, |mut state| -> Result<_, ContractError> {
        state.count += amount;
        Ok(state)
    })?;

    Ok(Response::new()
        .add_attribute("method", "increment")
        .add_attribute("amount", amount.to_string())
        .add_attribute("sender", info.sender.to_string()))
}

pub fn execute_decrement(deps: DepsMut) -> Result<Response, ContractError> {
    STATE.update(deps.storage, |mut state| -> Result<_, ContractError> {
        state.count -= 1;
        Ok(state)
    })?;

    Ok(Response::new().add_attribute("method", "decrement"))
}

pub fn execute_reset(
    deps: DepsMut,
    info: MessageInfo,
    count: i32,
) -> Result<Response, ContractError> {
    STATE.update(deps.storage, |mut state| -> Result<_, ContractError> {
        if info.sender != state.owner {
            return Err(ContractError::Unauthorized {});
        }
        state.count = count;
        Ok(state)
    })?;
    Ok(Response::new().add_attribute("method", "reset"))
}

pub fn execute_add_to_whitelist(
    deps: DepsMut,
    info: MessageInfo,
    address: String,
) -> Result<Response, ContractError> {
    let state = STATE.load(deps.storage)?;

    // only the owner can add to the whitelist
    if info.sender != state.owner {
        return Err(ContractError::Unauthorized {});
    }

    let addr = deps.api.addr_validate(&address)?;

    // check if the address is already in the whitelist
    let is_whitelisted = WHITELIST.may_load(deps.storage, &addr)?.unwrap_or(false);
    if is_whitelisted {
        return Err(ContractError::AlreadyWhitelisted {});
    }

    WHITELIST.save(deps.storage, &addr, &true)?;

    Ok(Response::new()
        .add_attribute("method", "add_to_whitelist")
        .add_attribute("address", address))
}

pub fn execute_remove_from_whitelist(
    deps: DepsMut,
    info: MessageInfo,
    address: String,
) -> Result<Response, ContractError> {
    let state = STATE.load(deps.storage)?;

    // only the owner can remove from the whitelist
    if info.sender != state.owner {
        return Err(ContractError::Unauthorized {});
    }

    let addr = deps.api.addr_validate(&address)?;

    // check if the address is in the whitelist
    let is_whitelisted = WHITELIST.may_load(deps.storage, &addr)?.unwrap_or(false);
    if !is_whitelisted {
        return Err(ContractError::NotWhitelisted {});
    }

    WHITELIST.remove(deps.storage, &addr);

    Ok(Response::new()
        .add_attribute("method", "remove_from_whitelist")
        .add_attribute("address", address))
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetCount {} => to_binary(&query_count(deps)?),
        QueryMsg::CheckPolicy { sender, msg_type, msg_data } => to_binary(&query_check_policy(deps, sender, msg_type, msg_data)?),
        QueryMsg::IsWhitelisted { address } => to_binary(&query_is_whitelisted(deps, address)?),
    }
}

fn query_count(deps: Deps) -> StdResult<GetCountResponse> {
    let state = STATE.load(deps.storage)?;
    Ok(GetCountResponse { count: state.count })
}

fn query_check_policy(deps: Deps, sender: String, msg_type: String, msg_data: String) -> StdResult<CheckPolicyResponse> {
    let sender_addr = deps.api.addr_validate(&sender)?;
    let is_whitelisted = WHITELIST.may_load(deps.storage, &sender_addr)?.unwrap_or(false);

    // Check eligibility based on message type and provide detailed reasons
    let (eligible, reason) = match msg_type.as_str() {
        "increment" => {
            // For increment messages, only whitelisted users are eligible
            // AND the amount must be less than 5
            if !is_whitelisted {
                (false, Some("User not in whitelist".to_string()))
            } else {
                // Strictly parse msg_data - any parsing error will fail the transaction
                let json_value = serde_json::from_str::<Value>(&msg_data)
                    .map_err(|e| cosmwasm_std::StdError::generic_err(format!("Failed to parse increment msg_data as JSON: {}", e)))?;
                
                // Extract amount field - missing or invalid amount will fail the transaction
                let amount = json_value.get("amount")
                    .and_then(|v| v.as_i64())
                    .ok_or_else(|| cosmwasm_std::StdError::generic_err("Missing or invalid 'amount' field in increment msg_data"))?;
                
                // Apply business logic: amount must be less than 5
                if amount < 5 {
                    (true, None) // Eligible, no reason needed
                } else {
                    (false, Some(format!("Amount {} exceeds maximum allowed (5)", amount)))
                }
            }
        }
        "decrement" => {
            // For decrement messages, strictly validate that msg_data is empty object
            let json_value = serde_json::from_str::<Value>(&msg_data)
                .map_err(|e| cosmwasm_std::StdError::generic_err(format!("Failed to parse decrement msg_data as JSON: {}", e)))?;
            
            // Decrement should only accept empty object {}
            if !json_value.as_object().map_or(false, |obj| obj.is_empty()) {
                return Err(cosmwasm_std::StdError::generic_err("Decrement message should be empty object {}, no additional fields allowed"));
            }
            
            // Check authorization: only non-whitelisted users are eligible  
            if !is_whitelisted {
                (true, None) // Eligible, no reason needed
            } else {
                (false, Some("Whitelisted users cannot use decrement".to_string()))
            }
        }
        "reset" => {
            // For reset messages, we need to check if sender is the contract owner
            // Parse msg_data to validate the reset parameters (strict validation)
            let json_value = serde_json::from_str::<Value>(&msg_data)
                .map_err(|e| cosmwasm_std::StdError::generic_err(format!("Failed to parse reset msg_data as JSON: {}", e)))?;
            
            // Validate that count field exists and is valid
            let _count = json_value.get("count")
                .and_then(|v| v.as_i64())
                .ok_or_else(|| cosmwasm_std::StdError::generic_err("Missing or invalid 'count' field in reset msg_data"))?;
            
            // Check if sender is the contract owner
            let state = STATE.load(deps.storage)?;
            if sender_addr == state.owner {
                (true, None) // Eligible, no reason needed
            } else {
                (false, Some("Only contract owner can reset".to_string()))
            }
        }
        _ => {
            // For unknown message types, fail the transaction
            return Err(cosmwasm_std::StdError::generic_err(format!("Unknown message type: {}", msg_type)));
        }
    };

    Ok(CheckPolicyResponse {
        eligible,
        reason,
    })
}

fn query_is_whitelisted(deps: Deps, address: String) -> StdResult<WhitelistResponse> {
    let addr = deps.api.addr_validate(&address)?;
    let is_whitelisted = WHITELIST.may_load(deps.storage, &addr)?.unwrap_or(false);

    Ok(WhitelistResponse { is_whitelisted })
}

#[cfg_attr(not(feature = "library"), entry_point)]
pub fn migrate(deps: DepsMut, _env: Env, _msg: MigrateMsg) -> Result<Response, ContractError> {
    set_contract_version(deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::new().add_attribute("method", "migrate"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};
    use cosmwasm_std::{coins, from_binary};

    #[test]
    fn proper_initialization() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg { initial_count: 17 };
        let info = mock_info("creator", &coins(1000, "earth"));

        // we can just call .unwrap() to assert this was a success
        let res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();
        assert_eq!(0, res.messages.len());

        // it worked, let's query the state
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
        let value: GetCountResponse = from_binary(&res).unwrap();
        assert_eq!(17, value.count);
    }

    #[test]
    fn increment_requires_whitelist() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg { initial_count: 17 };
        let info = mock_info("creator", &coins(2, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // try to increment the count, but the user is not whitelisted, should fail
        let info = mock_info("user1", &coins(2, "token"));
        let msg = ExecuteMsg::Increment { amount: 1 };
        let res = execute(deps.as_mut(), mock_env(), info, msg);
        match res {
            Err(ContractError::NotWhitelisted {}) => {}
            _ => panic!("Must return NotWhitelisted error"),
        }
    }

    #[test]
    fn whitelist_management() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg { initial_count: 17 };
        let creator_info = mock_info("creator", &coins(2, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), creator_info.clone(), msg).unwrap();

        // add user to the whitelist
        let msg = ExecuteMsg::AddToWhitelist {
            address: "user1".to_string(),
        };
        let _res = execute(deps.as_mut(), mock_env(), creator_info.clone(), msg).unwrap();

        // check if the user is in the whitelist
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::IsWhitelisted {
                address: "user1".to_string(),
            },
        )
        .unwrap();
        let value: WhitelistResponse = from_binary(&res).unwrap();
        assert_eq!(true, value.is_whitelisted);

        // test CheckPolicy for increment - should be eligible for whitelisted user with amount < 5
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::CheckPolicy {
                sender: "user1".to_string(),
                msg_type: "increment".to_string(),
                msg_data: r#"{"amount": 3}"#.to_string(),
            },
        )
        .unwrap();
        let value: CheckPolicyResponse = from_binary(&res).unwrap();
        assert_eq!(true, value.eligible);

        // test CheckPolicy for decrement - should not be eligible for whitelisted user
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::CheckPolicy {
                sender: "user1".to_string(),
                msg_type: "decrement".to_string(),
                msg_data: "{}".to_string(),
            },
        )
        .unwrap();
        let value: CheckPolicyResponse = from_binary(&res).unwrap();
        assert_eq!(false, value.eligible);

        // now the user should be able to increment the count
        let user_info = mock_info("user1", &coins(2, "token"));
        let msg = ExecuteMsg::Increment { amount: 1 };
        let _res = execute(deps.as_mut(), mock_env(), user_info, msg).unwrap();

        // check if the count is incremented
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
        let value: GetCountResponse = from_binary(&res).unwrap();
        assert_eq!(18, value.count);

        // remove user from the whitelist
        let msg = ExecuteMsg::RemoveFromWhitelist {
            address: "user1".to_string(),
        };
        let _res = execute(deps.as_mut(), mock_env(), creator_info, msg).unwrap();

        // check if the user is not in the whitelist
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::IsWhitelisted {
                address: "user1".to_string(),
            },
        )
        .unwrap();
        let value: WhitelistResponse = from_binary(&res).unwrap();
        assert_eq!(false, value.is_whitelisted);

        // test CheckPolicy for non-whitelisted user with decrement - should be eligible
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::CheckPolicy {
                sender: "user1".to_string(),
                msg_type: "decrement".to_string(),
                msg_data: "{}".to_string(),
            },
        )
        .unwrap();
        let value: CheckPolicyResponse = from_binary(&res).unwrap();
        assert_eq!(true, value.eligible);

        // test CheckPolicy for non-whitelisted user with increment - should not be eligible  
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::CheckPolicy {
                sender: "user1".to_string(),
                msg_type: "increment".to_string(),
                msg_data: r#"{"amount": 3}"#.to_string(),
            },
        )
        .unwrap();
        let value: CheckPolicyResponse = from_binary(&res).unwrap();
        assert_eq!(false, value.eligible);
    }

    #[test]
    fn check_policy_increment_amount_limits() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg { initial_count: 17 };
        let creator_info = mock_info("creator", &coins(2, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), creator_info.clone(), msg).unwrap();

        // Add user to whitelist first
        let msg = ExecuteMsg::AddToWhitelist {
            address: "user1".to_string(),
        };
        let _res = execute(deps.as_mut(), mock_env(), creator_info, msg).unwrap();

        // Test increment with amount < 5 - should be eligible
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::CheckPolicy {
                sender: "user1".to_string(),
                msg_type: "increment".to_string(),
                msg_data: r#"{"amount": 3}"#.to_string(),
            },
        )
        .unwrap();
        let value: CheckPolicyResponse = from_binary(&res).unwrap();
        assert_eq!(true, value.eligible);

        // Test increment with amount >= 5 - should not be eligible
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::CheckPolicy {
                sender: "user1".to_string(),
                msg_type: "increment".to_string(),
                msg_data: r#"{"amount": 5}"#.to_string(),
            },
        )
        .unwrap();
        let value: CheckPolicyResponse = from_binary(&res).unwrap();
        assert_eq!(false, value.eligible);
        assert_eq!(value.reason, Some("Amount 5 exceeds maximum allowed (5)".to_string()));

        // Test increment with amount > 5 - should not be eligible
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::CheckPolicy {
                sender: "user1".to_string(),
                msg_type: "increment".to_string(),
                msg_data: r#"{"amount": 10}"#.to_string(),
            },
        )
        .unwrap();
        let value: CheckPolicyResponse = from_binary(&res).unwrap();
        assert_eq!(false, value.eligible);
        assert_eq!(value.reason, Some("Amount 10 exceeds maximum allowed (5)".to_string()));

        // Test increment with invalid msg_data - should fail with error
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::CheckPolicy {
                sender: "user1".to_string(),
                msg_type: "increment".to_string(),
                msg_data: r#"{"invalid": "data"}"#.to_string(),
            },
        );
        // Should fail due to missing amount field
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err.to_string().contains("Missing or invalid 'amount' field"));

        // Test increment with malformed JSON - should fail with error
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::CheckPolicy {
                sender: "user1".to_string(),
                msg_type: "increment".to_string(),
                msg_data: r#"{"amount": invalid_json}"#.to_string(),
            },
        );
        // Should fail due to JSON parsing error
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err.to_string().contains("Failed to parse increment msg_data as JSON"));

        // Test decrement with invalid fields - should fail with error
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::CheckPolicy {
                sender: "user2".to_string(), // non-whitelisted user
                msg_type: "decrement".to_string(),
                msg_data: r#"{"amount": 1}"#.to_string(), // invalid field
            },
        );
        // Should fail due to extra fields in decrement message
        assert!(res.is_err());
        let err = res.unwrap_err();
        assert!(err.to_string().contains("no additional fields allowed"));

        // Test decrement with valid empty object - should succeed for non-whitelisted user
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::CheckPolicy {
                sender: "user2".to_string(), // non-whitelisted user (not added to whitelist)
                msg_type: "decrement".to_string(),
                msg_data: "{}".to_string(), // valid empty object
            },
        )
        .unwrap();
        let value: CheckPolicyResponse = from_binary(&res).unwrap();
        assert_eq!(true, value.eligible);
        assert_eq!(value.reason, None);
    }

    #[test]
    fn check_policy_reset_message() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg { initial_count: 17 };
        let creator_info = mock_info("creator", &coins(2, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), creator_info, msg).unwrap();

        // test CheckPolicy for reset message - creator should be eligible
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::CheckPolicy {
                sender: "creator".to_string(),
                msg_type: "reset".to_string(),
                msg_data: r#"{"count": 10}"#.to_string(),
            },
        )
        .unwrap();
        let value: CheckPolicyResponse = from_binary(&res).unwrap();
        assert_eq!(true, value.eligible);

        // test CheckPolicy for reset message - non-creator should not be eligible
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::CheckPolicy {
                sender: "user1".to_string(),
                msg_type: "reset".to_string(),
                msg_data: r#"{"count": 10}"#.to_string(),
            },
        )
        .unwrap();
        let value: CheckPolicyResponse = from_binary(&res).unwrap();
        assert_eq!(false, value.eligible);
    }

    #[test]
    fn unauthorized_whitelist_management() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg { initial_count: 17 };
        let creator_info = mock_info("creator", &coins(2, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), creator_info, msg).unwrap();

        // non-owner trying to add to whitelist, should fail
        let user_info = mock_info("user1", &coins(2, "token"));
        let msg = ExecuteMsg::AddToWhitelist {
            address: "user2".to_string(),
        };
        let res = execute(deps.as_mut(), mock_env(), user_info, msg);
        match res {
            Err(ContractError::Unauthorized {}) => {}
            _ => panic!("Must return Unauthorized error"),
        }
    }

    #[test]
    fn reset() {
        let mut deps = mock_dependencies();

        let msg = InstantiateMsg { initial_count: 17 };
        let info = mock_info("creator", &coins(2, "token"));
        let _res = instantiate(deps.as_mut(), mock_env(), info, msg).unwrap();

        // beneficiary can release it
        let unauth_info = mock_info("anyone", &coins(2, "token"));
        let msg = ExecuteMsg::Reset { count: 5 };
        let res = execute(deps.as_mut(), mock_env(), unauth_info, msg);
        match res {
            Err(ContractError::Unauthorized {}) => {}
            _ => panic!("Must return unauthorized error"),
        }

        // only the original creator can reset the counter
        let auth_info = mock_info("creator", &coins(2, "token"));
        let msg = ExecuteMsg::Reset { count: 5 };
        let _res = execute(deps.as_mut(), mock_env(), auth_info, msg).unwrap();

        // should now be 5
        let res = query(deps.as_ref(), mock_env(), QueryMsg::GetCount {}).unwrap();
        let value: GetCountResponse = from_binary(&res).unwrap();
        assert_eq!(5, value.count);
    }
}
