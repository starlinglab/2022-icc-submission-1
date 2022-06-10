import copy
import json
import logging
import os
import requests
import shutil
import sys
import zipfile

_NUMBERS_API_KEY="NUMBERS_API_KEY"
_NUMBERS_API_URL="NUMBERS_API_URL"
_REGISTER = _NUMBERS_API_URL + "/nit_create_asset"

_ORG_ID="hala-systems"
_COLLECTION_ID="submission-1-kharkiv-photos"
_CUSTODY_TOKEN_CONTRACT_ADDRESS="CUSTODY_TOKEN_CONTRACT_ADDRESS"

# Content of this file is fetched from inspecting traffic while scrolling through all transactions
# using a web browser at https://likecoin.bigdipper.live/accounts/cosmos1z7a4z9vzs83xau2y9wfaudplshu9les0wfvnqp
_ISCN_FILE="./iscn/iscn.json"

# Content of this folder are downloaded from the output of Integrity Backend's 'action-archive' in Dropbox
_RECEIPTS_DIR="./receipts-kharkiv-photos"

# Content of this folder are unencrypted archives downloaded from the internal directory of Integrity Backend
# Do not commit this directory
_ARCHIVE_ZIPS_DIR="./archive-zips"

logging.basicConfig(
    stream=sys.stdout,
    level=logging.INFO,
    format="[%(asctime)s] {%(filename)s:%(lineno)d} %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S%z",
)
_logger = logging.getLogger(__name__)

def register_zip(
    org_id,
    collection_id,
    content_sha,
    content_md5,
    content_cid,
    zip_sha,
    zip_md5,
    zip_cid,
    enc_zip_sha,
    enc_zip_md5,
    enc_zip_cid,
    extracted_meta_content,
):
    """Registers encrypted ZIP on Numbers Protocol.
    """
    numbers_receipt = None
    try:
        with open(extracted_meta_content) as meta_content_f:
            meta_content = json.load(meta_content_f)["contentMetadata"]
            asset_extras = {
                "author": meta_content["author"],
                "usageInfo": "Encrypted with AES-256.",
                "keywords": [org_id, collection_id],
                "extras": meta_content["extras"],
                "contentFingerprints": [
                    f"hash://sha256/{enc_zip_sha}",
                    f"hash://md5/{enc_zip_md5}",
                    f"ipfs://{enc_zip_cid}",
                ],
                "relatedContent": [
                    {
                        "value": f"hash://sha256/{content_sha}",
                        "description": "The SHA-256 of the original content.",
                    },
                    {
                        "value": f"hash://md5/{content_md5}",
                        "description": "The MD5 of the original content.",
                    },
                    {
                        "value": f"ipfs://{content_cid}",
                        "description": "The CID of the original content.",
                    },
                    {
                        "value": f"hash://sha256/{zip_sha}",
                        "description": "The SHA-256 of the unencrypted archive.",
                    },
                    {
                        "value": f"hash://md5/{zip_md5}",
                        "description": "The MD5 of the unencrypted archive.",
                    },
                    {
                        "value": f"ipfs://{zip_cid}",
                        "description": "The CID of the unencrypted archive.",
                    },
                ],
            }
            numbers_receipt = register(
                meta_content["name"],
                meta_content["description"],
                enc_zip_cid,
                enc_zip_sha,
                "application/octet-stream",
                meta_content["dateCreated"],
                asset_extras,
                _CUSTODY_TOKEN_CONTRACT_ADDRESS,
            )
            if numbers_receipt is not None:
                print(f"{numbers_receipt}")
                print("")
            else:
                _logger.error(
                    "Content registration on Numbers Protocol failed"
                )
        
    except Exception as e:
        _logger.error(f"Content registration on Numbers Protocol failed: {e}")

def register(
    asset_name,
    asset_description,
    asset_cid,
    asset_sha256,
    asset_mime_type,
    asset_timestamp_created,
    asset_extras,
    nft_contract_address,
):
    """Registers an asset to the integrity blockchain.

    https://github.com/numbersprotocol/enterprise-service/wiki/7.-Nit,-Native-Protocol-Tool#nit-create-asset

    Args:
        asset_name: name of the asset
        asset_description: description of the asset
        asset_cid: CID of the asset
        asset_sha256: SHA-256 of the asset
        asset_mime_type: MIME type of asset (use 'application/octet-stream' for encrypted assets)
        asset_timestamp_created: creation timestamp of the asset
        asset_extras: extra JSON object to be included in asset registration
        nft_contract_address: Avalanche contract address for minting an ERC-721 custody token for the asset; None to skip

    Returns:
        Numbers registration receipt if the registration succeeded; None otherwise
    """
    custom = copy.copy(asset_extras)
    custom.update({"name": asset_name})
    custom.update({"description": asset_description})

    if not nft_contract_address:
        registration_data = [
            ("assetCid", asset_cid),
            ("assetSha256", asset_sha256),
            ("assetMimetype", asset_mime_type),
            ("assetTimestampCreated", asset_timestamp_created),
            ("custom", json.dumps(custom)),
        ]
    else:
        nft_metadata = {
            "name": asset_name,
            "description": asset_description,
            "external_url": f"ipfs://{asset_cid}",
            "custom": custom,
        }

        registration_data = [
            ("assetCid", asset_cid),
            ("assetSha256", asset_sha256),
            ("assetMimetype", asset_mime_type),
            ("assetTimestampCreated", asset_timestamp_created),
            ("custom", json.dumps(custom)),
            ("nftContractAddress", nft_contract_address),
            ("nftMetadata", json.dumps(nft_metadata)),
        ]

    resp = requests.post(
        _REGISTER,
        headers={"Authorization": f"Bearer {_NUMBERS_API_KEY}"},
        data=registration_data,
    )

    if not resp.ok:
        _logger.error(
            f"Numbers registration failed: {resp.status_code} {resp.text}"
        )
        return None

    data = resp.json()
    if data.get("response") is None:
        _logger.warning(
            "Numbers registration response did not have the 'response' field: %s",
            resp.text,
        )
        return None

    return data["response"]

def main():
    # Construct a map of ISCN records from chain data
    iscn_records = {}
    if os.path.isfile(_ISCN_FILE):
        with open(_ISCN_FILE, "r") as f:
            pages = json.loads(f.read())
            for page in pages:
                transactions = page['data']['messagesByAddress']
                for transaction in transactions:
                    fingerprints = transaction['transaction']['messages'][0].get('record', {}).get('contentFingerprints', {})
                    txhash = transaction['transaction']['hash']
                    for fingerprint in fingerprints:
                        iscn_records[fingerprint.split("/")[-1]] = txhash

    # Iterate through receipts
    print("--- Registration transaction hashes by CID ---")
    print("")
    missing_records = {}
    files = os.listdir(_RECEIPTS_DIR)
    for file in files:
        path = os.path.join(_RECEIPTS_DIR, file)
        if os.path.isfile(path):
            with open(path, "r") as f:
                receipt = json.loads(f.read())
                cid = receipt['archiveEncrypted']['cid']

                # The first archives failed registration to Numbers Protocol and did not mint custody tokens
                # This identifies which ones are missing in the receipts so they can be manually registered
                numbers = receipt.get('registrationRecords', {}).get('numbersProtocol', {}).get('txHash')

                # The ISCN are sometimes registered on chain, but not included in the receipts due to a client bug
                # This fills the txHash from chain data downloaded into _ISCN_FILE from bigdipper
                iscn = receipt.get('registrationRecords', {}).get('iscn', {}).get('txHash', iscn_records[cid])
                print(f"|`{cid}`|`{numbers}`|`{iscn}`|")
                if not numbers:
                    missing_records[cid] = receipt
    print("")

    # Print records with missing registrations and custody tokens
    print("--- Missing Numbers Protocol registrations and custody token mints ---")
    print("")
    print(missing_records)
    print("")

    # Register missing records to Numbers Protocol and mint custody tokens at _CUSTODY_TOKEN_CONTRACT_ADDRESS
    print("--- Registration and mint of missing records ---")
    print("")
    for record in missing_records:
        r = missing_records[record]
        print(r)
        print("")

        # Unzip content metadata from archive
        try:
            os.makedirs("tmp")
        except Exception as e:
            pass

        extracted_meta_content = f"tmp/{r['archiveEncrypted']['cid']}.json"
        with zipfile.ZipFile(f"{_ARCHIVE_ZIPS_DIR}/{r['archive']['sha256']}.zip", "r") as zipf:
            with zipf.open(f"{r['content']['sha256']}-meta-content.json") as zippedf, open(extracted_meta_content, "wb") as f:
                shutil.copyfileobj(zippedf, f)

        # Register missing record
        print(f"Extracted content metadata: {extracted_meta_content}")
        print("")

        # Used to select a specific CID to register
        # if r['archiveEncrypted']['cid'] == "bafybeibhkd37eteh5eykn36im4gyspwihrxbgvr23fhxmzwu46qjampnci":
        register_zip(
            _ORG_ID,
            _COLLECTION_ID,
            r['content']['sha256'],
            r['content']['md5'],
            r['content']['cid'],
            r['archive']['sha256'],
            r['archive']['md5'],
            r['archive']['cid'],
            r['archiveEncrypted']['sha256'],
            r['archiveEncrypted']['md5'],
            r['archiveEncrypted']['cid'],
            extracted_meta_content,
        )
        print("---")
        print("")

if __name__ == '__main__':
    main()
