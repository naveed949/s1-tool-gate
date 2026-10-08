"""kaia-mcp fixture: real tool names and scopes.

Source of truth: naveed949/kaia-mcp@253d6c8 ``src/auth/scopes.ts`` (TOOL_SCOPES)
and ``src/auth/constants.ts`` (SCOPES); the map is unchanged since db76732 and
still identical at 00f3511 and 5794969 (MCP SDK v2, the live e2e pin). Keep
this list in sync by hand; the claims gate denies any tool not listed here
(``claims_unknown_tool``). ``claims_gate.proxy`` refuses to start if a live
kaia-mcp publishes a different map.
"""

from __future__ import annotations

from claims_gate.policy import ToolPolicy

KAIA_READ = "kaia:read"
KAIA_ENCODE = "kaia:encode"
KAIA_WALLET = "kaia:wallet"

KAIA_SOURCE = "naveed949/kaia-mcp@253d6c8:src/auth/scopes.ts"

KAIA_READ_TOOLS: tuple[str, ...] = (
    "get_kaia_balance",
    "get_account_info",
    "get_account_tokens",
    "get_account_nfts",
    "get_transaction",
    "get_transaction_receipt",
    "get_account_transactions",
    "estimate_gas",
    "get_block_number",
    "get_block",
    "get_block_rewards",
    "get_token_info",
    "get_token_holders",
    "get_token_transfers",
    "get_token_allowance",
    "get_nft_info",
    "get_nft_item",
    "get_nft_transfers",
    "read_contract",
    "get_contract_abi",
    "get_contract_source",
    "get_gas_price",
    "get_kaia_price",
    "get_chain_info",
)

KAIA_TOOL_SCOPES: dict[str, str] = {
    **{name: KAIA_READ for name in KAIA_READ_TOOLS},
    "encode_function_data": KAIA_ENCODE,
    "generate_wallet": KAIA_WALLET,
}

# generate_wallet returns a private key when kaia-mcp's unsafe flag is on.
# The gate never silently allows it, even with kaia:wallet.
KAIA_WALLET_TOOLS: frozenset[str] = frozenset({"generate_wallet"})


def kaia_policy(wallet_default: str = "escalate") -> ToolPolicy:
    return ToolPolicy(
        tool_scopes=KAIA_TOOL_SCOPES,
        wallet_tools=KAIA_WALLET_TOOLS,
        wallet_default=wallet_default,  # type: ignore[arg-type]
    )
