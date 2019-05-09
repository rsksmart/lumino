RNS_RESOLVER_ADDRESS = "0x4efd25e3d348f8f25a14fb7655fba6f72edfe93a"
RNS_RESOLVER_ABI = [
{
    "inputs": [
    {
        "name": "rnsAddr",
        "type": "address"
    }
    ],
    "payable": "false",
    "stateMutability": "nonpayable",
    "type": "constructor"
},
{
    "payable": "false",
    "stateMutability": "nonpayable",
    "type": "fallback"
},
{
    "constant": "true",
    "inputs": [
    {
        "name": "node",
        "type": "bytes32"
    },
    {
        "name": "kind",
        "type": "bytes32"
    }
    ],
    "name": "has",
    "outputs": [
    {
        "name": "",
        "type": "bool"
    }
    ],
    "payable": "false",
    "stateMutability": "view",
    "type": "function"
},
{
    "constant": "true",
    "inputs": [
    {
        "name": "interfaceID",
        "type": "bytes4"
    }
    ],
    "name": "supportsInterface",
    "outputs": [
    {
        "name": "",
        "type": "bool"
    }
    ],
    "payable": "false",
    "stateMutability": "pure",
    "type": "function"
},
{
    "constant": "true",
    "inputs": [
    {
        "name": "node",
        "type": "bytes32"
    }
    ],
    "name": "addr",
    "outputs": [
    {
        "name": "",
        "type": "address"
    }
    ],
    "payable": "false",
    "stateMutability": "view",
    "type": "function"
},
{
    "constant": "false",
    "inputs": [
    {
        "name": "node",
        "type": "bytes32"
    },
    {
        "name": "addrValue",
        "type": "address"
    }
    ],
    "name": "setAddr",
    "outputs": [],
    "payable": "false",
    "stateMutability": "nonpayable",
    "type": "function"
},
{
    "constant": "true",
    "inputs": [
    {
        "name": "node",
        "type": "bytes32"
    }
    ],
    "name": "content",
    "outputs": [
    {
        "name": "",
        "type": "bytes32"
    }
    ],
    "payable": "false",
    "stateMutability": "view",
    "type": "function"
},
{
    "constant": "false",
    "inputs": [
    {
        "name": "node",
        "type": "bytes32"
    },
    {
        "name": "hash",
        "type": "bytes32"
    }
    ],
    "name": "setContent",
    "outputs": [],
    "payable": "false",
    "stateMutability": "nonpayable",
    "type": "function"
}
]
RNS_ADDRESS_ZERO = "0x0000000000000000000000000000000000000000"
