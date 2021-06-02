#!/bin/bash
set -euox pipefail

# Colorful output.
function greenprint {
  echo -e "\033[1;32m${1}\033[0m"
}

# Get OS and architecture details.
source /etc/os-release
ARCH=$(uname -m)

# Dumps details about the instance running the CI job.
CPUS=$(nproc)
MEM=$(free -m | grep -oP '\d+' | head -n 1)
DISK=$(df --output=size -h / | sed '1d;s/[^0-9]//g')
HOSTNAME=$(uname -n)
USER=$(whoami)
ARCH=$(uname -m)
KERNEL=$(uname -r)

echo -e "\033[0;36m"
cat << EOF
------------------------------------------------------------------------------
CI MACHINE SPECS
------------------------------------------------------------------------------
     Hostname: ${HOSTNAME}
         User: ${USER}
         CPUs: ${CPUS}
          RAM: ${MEM} MB
         DISK: ${DISK} GB
         ARCH: ${ARCH}
       KERNEL: ${KERNEL}
------------------------------------------------------------------------------
EOF
echo -e "\033[0m"

# # Prepare osbuild-composer repository file
# sudo mkdir -p /etc/osbuild-composer/repositories

# # Set os-variant and boot location used by virt-install.
# case "${ID}-${VERSION_ID}" in
#     "rhel-8.3")
#         COMMIT_IMAGE_TYPE=rhel-edge-commit
#         OSTREE_REF="rhel/8/${ARCH}/edge"
#         OS_VARIANT="rhel8.3"
#         BOOT_LOCATION="http://download-node-02.eng.bos.redhat.com/rhel-8/rel-eng/updates/RHEL-8/latest-RHEL-8.3.1/compose/BaseOS/x86_64/os/"
#         sudo cp files/rhel-8-3-1.json /etc/osbuild-composer/repositories/rhel-8.json;;
#     "rhel-8.4")
#         COMMIT_IMAGE_TYPE=rhel-edge-commit
#         CONTAINER_IMAGE_TYPE=rhel-edge-container
#         INSTALLER_IMAGE_TYPE=rhel-edge-installer
#         CONTAINER_FILENAME=rhel84-container.tar
#         INSTALLER_FILENAME=rhel84-boot.iso
#         OSTREE_REF="rhel/8/${ARCH}/edge"
#         OS_VARIANT="rhel8-unknown"
#         BOOT_LOCATION="http://download-node-02.eng.bos.redhat.com/rhel-8/rel-eng/RHEL-8/latest-RHEL-8.4.0/compose/BaseOS/x86_64/os/"
#         sudo cp files/rhel-8-4-0.json /etc/osbuild-composer/repositories/rhel-8-beta.json
#         sudo ln -sf /etc/osbuild-composer/repositories/rhel-8-beta.json /etc/osbuild-composer/repositories/rhel-8.json;;
#     "rhel-8.5")
#         COMMIT_IMAGE_TYPE=edge-commit
#         CONTAINER_IMAGE_TYPE=edge-container
#         INSTALLER_IMAGE_TYPE=edge-installer
#         CONTAINER_FILENAME=container.tar
#         INSTALLER_FILENAME=installer.iso
#         OSTREE_REF="rhel/8/${ARCH}/edge"
#         OS_VARIANT="rhel8-unknown"
#         sudo cp files/rhel-8-5-0.json /etc/osbuild-composer/repositories/rhel-8-beta.json
#         sudo ln -sf /etc/osbuild-composer/repositories/rhel-8-beta.json /etc/osbuild-composer/repositories/rhel-8.json;;
#     *)
#         echo "unsupported distro: ${ID}-${VERSION_ID}"
#         exit 1;;
# esac

# Set up environment variables
CERTDIR=/etc/osbuild-composer
CADIR=/etc/osbuild-composer-test/ca
IMAGE_BUILDER_NETWORK_NAME=image-builder
IMAGE_BUILDER_NETWORK_NET="192.168.255.0/24"
POSTGRES_IP=192.168.255.2
IMAGE_BUILDER_IP=192.168.255.1
DB_MIGRATION_IP=192.168.255.3
OSBUILD_COMPOSER_IP=192.168.255.254

# Set up temporary files.
TEMPDIR=$(mktemp -d)
OPENSSL_CONFIG=${TEMPDIR}/openssl.cnf
OSBUILD_COMPOSER_TOML=/etc/osbuild-composer/osbuild-composer.toml

greenprint "🏎️ Enabling fastestmirror to speed up dnf"
echo -e "fastestmirror=1" | sudo tee -a /etc/dnf/dnf.conf

# Install requirements for building RPMs in mock.
greenprint "📦 Installing build requirements"
sudo dnf -y install git podman

# List all installed packages
greenprint "📑 List of installed packages:"
rpm -qa | sort
echo "------------------------------------------------------------------------------"

# Clone latest image-builder source code
greenprint "📥 Clone image-builder source code"
GIT_REPO_URL=${1:-"https://github.com/osbuild/image-builder.git"}
GIT_BRANCH=${2:-"main"}
git clone --depth=1 -b "$GIT_BRANCH" "$GIT_REPO_URL" image-builder

# Clear container running env
greenprint "🧹 Clearing container running env"
# Remove any status containers if exist
sudo podman ps -a -q --format "{{.ID}}" | sudo xargs --no-run-if-empty podman rm -f
# Remove all images
sudo podman rmi -f -a

# Build image-builder container image first
greenprint "🛠 Build image-builder container image"
pushd image-builder
    sudo podman build --security-opt "label=disable" -t image-builder -f distribution/Dockerfile-ubi .
popd

# Configure osbuild-composer.toml
greenprint "🔧 Configure osbuild-composer.toml"
sudo tee "$OSBUILD_COMPOSER_TOML" > /dev/null << EOF
[worker]
allowed_domains = [ "osbuild.org", "client.osbuild.org", "osbuild-composer-api.test" ]
ca = "/etc/osbuild-composer/ca-crt.pem"
EOF

# Generate all X.509 certificates for the tests
greenprint "⚙️ Generate openssl.cnf"
sudo tee "$OPENSSL_CONFIG" > /dev/null << EOF
#
# ca options
#

[ca]
default_ca = osbuild_ca

[osbuild_ca]
database        = ./index.txt
new_certs_dir   = ./certs
rand_serial     = yes

certificate     = ca.cert.pem
private_key     = private/ca.key.pem

default_days    = 3650
default_md      = sha256

x509_extensions = osbuild_ca_ext

# See WARNINGS in 'man openssl ca'. This is ok, becasue it only copies
# extensions that are not already specified in 'osbuild_ca_ext'.
copy_extensions = copy

preserve        = no
policy          = osbuild_ca_policy

# We want to issue multiple certificates with the same subject in the
# testing environment.
unique_subject  = no


[osbuild_ca_ext]
basicConstraints       = critical, CA:TRUE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid:always, issuer:always
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign


[osbuild_ca_policy]
commonName   = supplied
emailAddress = supplied


#
# Extensions for server certificates
#

[osbuild_server_ext]
basicConstraints       = critical, CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid, issuer:always
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth


#
# Extensions for client certificates
#

[osbuild_client_ext]
basicConstraints       = CA:FALSE
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid,issuer
keyUsage               = critical, nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage       = clientAuth


#
# req options
#

[req]
default_md         = sha256
default_bits       = 2048
distinguished_name = osbuild_distinguished_name


#
# Only prompt for CN
#

[osbuild_distinguished_name]
CN = Common Name
emailAddress = E-Mail Address
EOF

# Configure CA folders
sudo rm -rf ${CADIR}
sudo mkdir -p ${CADIR}

pushd ${CADIR}
    sudo mkdir certs private
    sudo touch index.txt

    # Generate self-signed CA cert
    greenprint "🗞 Generate self-signed CA cert"
    sudo openssl req -config "$OPENSSL_CONFIG" \
        -keyout private/ca.key.pem \
        -new -nodes -x509 -extensions osbuild_ca_ext \
        -out ca.cert.pem -subj "/CN=osbuild.org"

    # Copy the private key to the location expected by the tests
    sudo cp ca.cert.pem "$CERTDIR"/ca-crt.pem

    # Generate a composer certificate.
    sudo openssl req -config "$OPENSSL_CONFIG" \
        -keyout "$CERTDIR/composer-key.pem" \
        -new -nodes \
        -out "$TEMPDIR/composer-csr.pem" \
        -subj "/CN=osbuild-composer-api.test/emailAddress=osbuild@example.com" \
        -addext "subjectAltName=DNS:osbuild-composer-api.test"

    sudo openssl ca -batch -config "$OPENSSL_CONFIG" \
        -extensions osbuild_server_ext \
        -in "$TEMPDIR/composer-csr.pem" \
        -out "$CERTDIR/composer-crt.pem"

    # user may not exist in GitHub CI but we don't care about file
    # ownership there
    if getent passwd _osbuild-composer; then
        sudo chown _osbuild-composer "$CERTDIR"/composer-*.pem
    fi

    # Generate a worker certificate.
    sudo openssl req -config "$OPENSSL_CONFIG" \
        -keyout "$CERTDIR/worker-key.pem" \
        -new -nodes \
        -out "$TEMPDIR/worker-csr.pem" \
        -subj "/CN=osbuild-composer-api.test/emailAddress=osbuild@example.com" \
        -addext "subjectAltName=DNS:osbuild-composer-api.test"

    sudo openssl ca -batch -config "$OPENSSL_CONFIG" \
        -extensions osbuild_client_ext \
        -in "$TEMPDIR/worker-csr.pem" \
        -out "$CERTDIR/worker-crt.pem"

    # Generate a client certificate.
    sudo openssl req -config "$OPENSSL_CONFIG" \
        -keyout "$CERTDIR/client-key.pem" \
        -new -nodes \
        -out "$TEMPDIR/client-csr.pem" \
        -subj "/CN=client.osbuild.org/emailAddress=osbuild@example.com" \
        -addext "subjectAltName=DNS:client.osbuild.org"

    sudo openssl ca -batch -config "$OPENSSL_CONFIG" \
        -extensions osbuild_client_ext \
        -in "$TEMPDIR/client-csr.pem" \
        -out "$CERTDIR/client-crt.pem"

    # Client keys are used by tests to access the composer APIs. Allow all users access.
    sudo chmod 644 "$CERTDIR/client-key.pem"

    # # Generate a kojihub certificate.
    # sudo openssl req -config "$OPENSSL_CONFIG" \
    #     -keyout "$CERTDIR"/kojihub-key.pem \
    #     -new -nodes \
    #     -out /tmp/kojihub-csr.pem \
    #     -subj "/CN=localhost/emailAddress=osbuild@example.com" \
    #     -addext "subjectAltName=DNS:localhost"

    # sudo openssl ca -batch -config "$OPENSSL_CONFIG" \
    #     -extensions osbuild_server_ext \
    #     -in /tmp/kojihub-csr.pem \
    #     -out "$CERTDIR"/kojihub-crt.pem
popd

# Start osbuild-composer and osbuild-composer-api
sudo systemctl enable --now osbuild-composer.socket
sudo systemctl enable --now osbuild-composer-api.socket

# In case osbuild-composer is running already
sudo systemctl try-restart osbuild-composer

# Basic verification
sudo composer-cli status show
sudo composer-cli sources list
for SOURCE in $(sudo composer-cli sources list); do
    sudo composer-cli sources info "$SOURCE"
done

# Prepare rhel-edge container network
greenprint "Prepare container network"
sudo podman network inspect "$IMAGE_BUILDER_NETWORK_NAME" >/dev/null 2>&1 || sudo podman network create --driver=bridge --subnet="$IMAGE_BUILDER_NETWORK_NET" --ip-range="$IMAGE_BUILDER_NETWORK_NET" --gateway="$OSBUILD_COMPOSER_IP" "$IMAGE_BUILDER_NETWORK_NAME"

# Start Postgres container
sudo podman run --name image-builder-db \
      --health-cmd "pg_isready -U postgres -d imagebuilder" --health-interval 2s \
      --health-timeout 2s --health-retries 10 \
      -e POSTGRES_USER=postgres \
      -e POSTGRES_PASSWORD=foobar \
      -e POSTGRES_DB=imagebuilder \
      --network "$IMAGE_BUILDER_NETWORK_NAME" \
      --ip "$POSTGRES_IP" \
      -d quay.io/osbuild/postgres:13-alpine

for RETRY in {1..10}; do
    if sudo podman healthcheck run image-builder-db  > /dev/null 2>&1; then
       break
    fi
    echo "Retrying in 2 seconds... $RETRY"
    sleep 2
done

# Migrate
sudo podman run --pull=never --security-opt "label=disable" \
     -e PGHOST="$POSTGRES_IP" -e PGPORT=5432 -e PGDATABASE=imagebuilder \
     -e PGUSER=postgres -e PGPASSWORD=foobar \
     -e MIGRATIONS_DIR="/app/migrations" \
     --network "$IMAGE_BUILDER_NETWORK_NAME" \
     --ip "$DB_MIGRATION_IP" \
     --name image-builder-migrate \
     image-builder /app/image-builder-migrate-db


# Start Image Builder container
sudo podman run -d --pull=never --security-opt "label=disable" \
     -e LISTEN_ADDRESS="${IMAGE_BUILDER_IP}:8086" \
     -e LOG_LEVEL=DEBUG \
     -e OSBUILD_URL="https://${OSBUILD_COMPOSER_IP}:443" \
     -e OSBUILD_CA_PATH=/etc/osbuild-composer/ca-crt.pem \
     -e OSBUILD_CERT_PATH=/etc/osbuild-composer/client-crt.pem \
     -e OSBUILD_KEY_PATH=/etc/osbuild-composer/client-key.pem \
     -e PGHOST="$POSTGRES_IP" -e PGPORT=5432 -e PGDATABASE=imagebuilder \
     -e PGUSER=postgres -e PGPASSWORD=foobar \
     -e ALLOWED_ORG_IDS="*" \
     -e DISTRIBUTIONS_DIR="/app/distributions" \
     -v /etc/osbuild-composer:/etc/osbuild-composer \
     --network "$IMAGE_BUILDER_NETWORK_NAME" \
     --ip "$IMAGE_BUILDER_IP" \
     --add-host "osbuild-composer-api.test:${OSBUILD_COMPOSER_IP}" \
     --name image-builder \
     image-builder
