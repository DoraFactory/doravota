use crate::error::ContractError;
use crate::msg::{
    CheckPolicyResponse, ExecuteMsg, GetCountResponse, InstantiateMsg, MigrateMsg, QueryMsg, WhitelistResponse,
};
use crate::state::{State, STATE, WHITELIST};
use cosmwasm_std::{
    entry_point, to_binary, Addr, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult,
};
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
        ExecuteMsg::Increment {} => execute_increment(deps, info),
        ExecuteMsg::Decrement {} => execute_decrement(deps),
        ExecuteMsg::Reset { count } => execute_reset(deps, info, count),
        ExecuteMsg::AddToWhitelist { address } => execute_add_to_whitelist(deps, info, address),
        ExecuteMsg::RemoveFromWhitelist { address } => {
            execute_remove_from_whitelist(deps, info, address)
        }
    }
}

pub fn execute_increment(deps: DepsMut, info: MessageInfo) -> Result<Response, ContractError> {
    // check if the user is whitelisted
    let is_whitelisted = WHITELIST
        .may_load(deps.storage, &info.sender)?
        .unwrap_or(false);
    if !is_whitelisted {
        return Err(ContractError::NotWhitelisted {});
    }

    STATE.update(deps.storage, |mut state| -> Result<_, ContractError> {
        state.count += 1;
        Ok(state)
    })?;

    Ok(Response::new()
        .add_attribute("method", "increment")
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
        QueryMsg::CheckPolicy { address } => to_binary(&query_check_policy(deps, address)?),
        QueryMsg::IsWhitelisted { address } => to_binary(&query_is_whitelisted(deps, address)?),
    }
}

fn query_count(deps: Deps) -> StdResult<GetCountResponse> {
    let state = STATE.load(deps.storage)?;
    Ok(GetCountResponse { count: state.count })
}

fn query_check_policy(deps: Deps, address: String) -> StdResult<CheckPolicyResponse> {
    let addr = deps.api.addr_validate(&address)?;
    let is_whitelisted = WHITELIST.may_load(deps.storage, &addr)?.unwrap_or(false);

    Ok(CheckPolicyResponse {
        eligible: is_whitelisted,
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
        let msg = ExecuteMsg::Increment {};
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

        // test CheckPolicy
        let res = query(
            deps.as_ref(),
            mock_env(),
            QueryMsg::CheckPolicy {
                address: "user1".to_string(),
            },
        )
        .unwrap();
        let value: CheckPolicyResponse = from_binary(&res).unwrap();
        assert_eq!(true, value.eligible);

        // now the user should be able to increment the count
        let user_info = mock_info("user1", &coins(2, "token"));
        let msg = ExecuteMsg::Increment {};
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
