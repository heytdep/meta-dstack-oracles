# trustless tee oracles

TEE-based infrastructure for running trustless oracles on GCP CVMs with TDX attestation.

## abstract

oracles are generally either safe and slow (multisig) or fast and trust-heavy (centralized). both suck for different reasons. multisigs are operationally constrained, limited to static data sources, and often provide weaker security than the systems consuming their data. centralized oracles are obviously trust-heavy.

this is a different approach: use TEEs as cryptographic anchors for oracle computation. the idea is simple - run your oracle code (e.g., a container that fetches vault prices from multiple RPCs and APIs) inside a hardware-backed trusted execution environment, get the TEE to attest that specific code is running, and have it sign the results with a key that only exists inside that attested environment.

the trust model isn't "zero trust" (nothing is), it's "relative trust requiring safety measures". we're pragmatic about it - permissioned operators, cloud-hosted hardware, geographic distribution across providers. the TEE minimizes (not eliminates) provider trust through remote attestation. attacking this requires physical access to specific hardware in specific data centers, not just compromising software.

see [trustless oracles research](https://www.xycloo.com/research/trustless-oracles.html) for the full motivation and threat model.

## what this does

this is a lightweight server that runs on GCP confidential VMs with TDX support. it does a few things:

1. **attested signing**: on startup, generates an ed25519 keypair inside the TEE and gets a TDX quote binding the public key to the hardware + OS measurements
2. **one-time pod deployment**: accepts multiple container deployments in a single initialization window, then locks down
3. **container attestation**: computes SHA384 hashes of pod configurations (excluding ConfigMap data), signs them with the TEE-endorsed key, and caches the signatures
4. **remote verification**: exposes an `/info` endpoint that returns the TEE public key, its attestation quote, all container hashes, and the signatures over those hashes

the quote binds the signer's public key to the TEE measurements. the signatures over container hashes prove what code is running. together, this lets anyone verify that specific container images are running inside a specific TEE environment.

## architecture

```
Within a gcp cvm (tdx):

1. meta-dstack server
  - on startup
    1. generate ed25519 keypair
    2. get TDX quote for pubkey -> cache
  - allows deploying podman containers
    1. accept pod YAMLs
    2. compute pod hashes (SHA384)
    3. deploy via podman
    4. sign hashes with TEE key -> cache
    5.  mark as initialized and reject future pods
  - verification happens through GET /info which returns the endorsed pubeky, a quote with such pubkey as report data, the container hashes and their respective signatures from the endorsed pubkey.
2. deployed oracle containers
  - these will generally fetch data from rpcs and apis, then whatever they want to expose as tee endorsed must be signed with the endorsed secret which is retrieved through a local-only api call from the container to this meta-dstack server.

## workflow

### 1. create the CVM

```bash
gcloud compute instances create "oracle-node-1" \
  --zone="us-east5-b" \
  --machine-type="c3-standard-4" \
  --image="meta-dstack-newversion" \
  --confidential-compute-type=TDX \
  --maintenance-policy=TERMINATE \
  --no-shielded-secure-boot \
  --no-shielded-vtpm
```

the instance boots with the meta-dstack server running. on startup it:
- generates the attested signer
- gets a TDX quote binding pubkey to hardware
- waits for pod deployments

### 2. deploy your oracle container(s)

you can deploy multiple pods in a single initialization window:

```bash
# deploy first container
curl -v \
  -X POST \
  --header "Content-Type: application/x-yaml" \
  --data-binary @"oracle-pod-1.yml" \
  "http://CVM_IP:3030/pods/deploy"

# deploy second container (optional)
curl -v \
  -X POST \
  --header "Content-Type: application/x-yaml" \
  --data-binary @"oracle-pod-2.yml" \
  "http://CVM_IP:3030/pods/deploy"

# finalize deployment (locks the node)
curl -X POST "http://CVM_IP:3030/pods/finalize"
```

after finalization:
- container hashes are signed
- node rejects further deployments
- `/info` endpoint returns complete attestation data

### 3. verify the deployment

```bash
curl http://CVM_IP:3030/info
```

returns:
```json
{
  "pubkey": "a1b2c3...",
  "quote": "040002008100...",
  "container_hashes": [
    "c084f54924...",
    "b1dd776d57..."
  ],
  "container_signatures": [
    "3a4b5c6d...",
    "7e8f9a0b..."
  ]
}
```

verification steps:
1. parse the TDX quote
2. extract REPORTDATA and verify it contains `sha256(pubkey)`
3. verify quote signature chain (Intel DCAP)
4. check MRTD/RTMR values match expected OS/kernel measurements
5. verify container signatures using the pubkey
6. verify container hashes match your expected images

### 4. oracle operation

your container can access the signing key:

```bash
# only works from localhost (within CVM)
curl http://127.0.0.1:3030/signer/secret
```

use this to sign oracle data:

```javascript
// in your oracle container
const signerSecret = await fetch('http://127.0.0.1:3030/signer/secret').then(r => r.text())
const oracleData = await computePrices() // your oracle logic
const signature = sign(oracleData, signerSecret)

// publish { data: oracleData, signature: signature }
```

consumers verify signatures against the TEE-attested pubkey.

## pod hash computation

pods are hashed deterministically to enable verification:

1. parse YAML -> JSON
2. remove `ConfigMap.data` and `ConfigMap.binaryData` (not measured, allows runtime config changes)
3. canonicalize JSON (sorted keys, sorted arrays by `name` field)
4. `SHA384(canonical_json)` = 48 bytes

this means changing your container image changes the hash (measured), but changing config values doesn't (not measured).

## endpoints

| method | path | description |
|--------|------|-------------|
| POST | `/pods/deploy` | deploy pod YAML (only before finalization) |
| POST | `/pods/finalize` | sign containers, lock deployment |
| GET | `/pods` | list deployed pod hashes |
| GET | `/info` | TEE pubkey + quote + container hashes + signatures |
| GET | `/signer/secret` | signing key (localhost only) |
| GET | `/quote/{data}` | get TDX quote with custom report data |
| GET | `/status` | health check |
| POST | `/logs/dump` | trigger log collection |
| GET | `/logs` | download collected logs |

## trust model

what you're trusting:

1. **intel TDX**: hardware-based isolation and attestation
2. **GCP infrastructure**: tier III/IV data centers, supply chain
3. **this codebase**: the server running inside the TEE
4. **container images**: the oracle code you deploy

mitigations:

- **open source**: audit the server code
- **reproducible builds**: verify the OS image measurements
- **geographic distribution**: run multiple nodes across clouds/regions
- **signature aggregation**: require M-of-N signatures from distributed nodes
- **non-anonymous operators**: accountability through known identities

attacking this requires:
- physical access to specific hardware in specific data centers
- or breaking TDX itself
- or supply chain compromise at scale

compare this to compromising a centralized oracle (software exploit) or a multisig (social engineering 4 of 7 keyholders).

## building

this uses Yocto to build a custom Linux image with the server baked in.

### setup

follow the guides (either yocto's or flashbots/yocto-manifests) to enable your image building os to work with yocto. if you're on ubuntu:

```bash
sudo apt update
sudo apt install gawk wget git diffstat unzip texinfo gcc build-essential chrpath socat cpio python3 python3-pip python3-pexpect xz-utils debianutils iputils-ping python3-git python3-jinja2 libegl1-mesa libsdl1.2-dev xterm python3-subunit mesa-common-dev zstd liblz4-tool chrpath diffstat lz4 mtools repo
sudo locale-gen en_US.UTF-8
```

create and initialize the multirepo directory:

```bash
mkdir yetanother; cd yetanother

repo init -u https://github.com/flashbots/yocto-manifests.git -b main -m tdx-base.xml

repo sync

source setup

cd srcs/poky;git clone https://github.com/tpluslabs/meta-dstack;cd ../../

chmod 777 srcs/poky/meta-dstack/get-modular.sh
```

run the `get-modular` script to apply the patches and add the dstack layer:

```bash
./srcs/poky/meta-dstack/get-modular.sh
```

> if you're deploying production set `PROD=true` before running the above script, it will apply the prod patches.

### build

```bash
cd srcs/poky/
bitbake core-image-minimal
```

the resulting image contains:
- minimal Linux kernel with TDX support
- podman for container management
- meta-dstack server at `/usr/bin/mini-server`
- systemd service to start server on boot

### GCP deployment

1. push the wic to a bucket (create one if needed: `gcloud storage buckets create "gs://tdx-gcp"`):

```bash
gsutil cp core-image-minimal-tdx-gcp.rootfs-{latest time tag}.wic.tar.gz gs://tdx-gcp
```

2. create custom image on gcp:

```bash
gcloud compute images create "meta-dstack-newversion" \
  --source-uri="gs://tdx-gcp/core-image-minimal-tdx-gcp.rootfs-20250522164856.wic.tar.gz" \
  --guest-os-features=UEFI_COMPATIBLE,VIRTIO_SCSI_MULTIQUEUE,GVNIC,TDX_CAPABLE
```

3. create the td vm instance:

```bash
gcloud compute instances create "oracle-node-1" \
  --zone="us-east5-b" \
  --machine-type="c3-standard-4" \
  --image="meta-dstack-newversion" \
  --confidential-compute-type=TDX \
  --maintenance-policy=TERMINATE \
  --no-shielded-secure-boot \
  --no-shielded-vtpm
```

> note: disable secure boot + vtpm so google's firmware measures according to spec.

## development

```bash
cd server
cargo build --release --features tdx

# test (without TDX)
cargo test

# run locally (mocked quotes)
cargo run
```

without the `tdx` feature, quotes are mocked for development. in production, build with `--features tdx` to use real TDX attestation.

## dependencies

the server needs:
- `tdx-attestation`: TDX quote generation via TSM
- `ed25519-dalek`: signing key operations
- `podman`: container orchestration
- `warp`: HTTP server
- `sha2`, `hex`, `serde_yaml`: hashing and serialization

## security notes

- the signing key never leaves the TEE
- `/signer/secret` only responds to localhost (checked via socket address)
- pod deployment is one-time to prevent runtime code changes
- ConfigMap data is excluded from measurements to allow runtime configuration
- quotes bind pubkey to both hardware identity and OS measurements

### critical: finalization and trust

**deployment and finalization are separate operations for a reason**. this has important security implications:

1. **unfinalized nodes are untrusted**: before `/pods/finalize` is called, the node can deploy arbitrary containers. the signer exists, but container signatures don't yet. consumers MUST NOT trust oracle data from unfinalized nodes.

2. **finalization freezes the state**: calling `/pods/finalize` signs all deployed container hashes and sets `initialized = true`. after this, no new pods can be deployed. the `/info` endpoint now returns the complete attestation bundle.

3. **consumers verify against expected hashes**: when a consumer calls `/info`, they MUST:
   - verify the TDX quote is valid and chains to Intel root of trust
   - extract the pubkey from quote's REPORTDATA
   - verify container_signatures match container_hashes using that pubkey
   - **compare container_hashes against locally computed expected values**

4. **the trust model**: you're trusting that:
   - the TEE correctly generated the signing key
   - the operator deployed the correct containers before finalizing
   - the container hashes in `/info` match what you expect

   if the hashes don't match your expectations, reject the oracle data regardless of valid signatures.

5. **workflow matters**:
   ```
   [untrusted] deploy pods -> [untrusted] more pods -> [trusted after verification] finalize
   ```

   the finalization step is the commitment. before it, the node is in setup phase. after it, the attestation bundle is complete and verifiable.

**example verification**:
```javascript
// consumer side
const info = await fetch('http://oracle-node:3030/info').then(r => r.json())

// 1. verify quote (DCAP verification)
const report = verifyQuote(info.quote)
const quotedPubkey = extractPubkeyFromReportData(report.reportData)
assert(quotedPubkey === info.pubkey)

// 2. verify container signatures
for (let i = 0; i < info.container_hashes.length; i++) {
  assert(verify(info.container_hashes[i], info.container_signatures[i], info.pubkey))
}

// 3. CRITICAL: verify hashes match expected values
const expectedHash = computePodHash(myOracleContainerSpec)
assert(info.container_hashes.includes(expectedHash))

// only now can you trust oracle data signed by info.pubkey
```

without step 3, an operator could deploy malicious containers, finalize them, and produce valid TEE-attested signatures for incorrect oracle data. the TEE attests "this code is running", not "this is the right code".

## why ed25519

we use ed25519 for signing because:
- deterministic signatures (no random nonce generation inside TEE)
- fast verification (important for on-chain oracle consumers)
- small signatures (64 bytes)
- well-supported across ecosystems

## future work

- support for RTMRs to bind pod hashes to TDX runtime measurements
- multi-node coordination and signature aggregation
- automated quote verification tooling
- on-chain quote verification contracts
- support for other TEE backends (SEV-SNP, etc)

## related work

- [trustless oracles research](https://www.xycloo.com/research/trustless-oracles.html) - motivation and threat model
- [Intel TDX](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/overview.html) - TEE architecture
- [GCP Confidential Computing](https://cloud.google.com/confidential-computing) - TDX-enabled VMs
- [DCAP](https://github.com/intel/SGXDataCenterAttestationPrimitives) - quote verification
- [flashbox](https://github.com/flashbots/flashbox/) - inspiration for this project

## license

MIT
