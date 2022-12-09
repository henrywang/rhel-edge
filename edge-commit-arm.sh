#!/bin/bash
set -exuo pipefail

# Get TEST_OS from $1
TEST_OS=$1

# Get OS data.
source /etc/os-release
ARCH=$(uname -m)

# SSH setup.
SSH_USER="admin"
SSH_OPTIONS=(-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5)
SSH_KEY=key/ostree_key

# Colorful output.
function greenprint {
    echo -e "\033[1;32m${1}\033[0m"
}

# Wait for the ssh server up to be.
wait_for_ssh_up () {
    SSH_STATUS=$(sudo ssh "${SSH_OPTIONS[@]}" -i "${SSH_KEY}" "${SSH_USER}@${1}" '/bin/bash -c "echo -n READY"')
    if [[ $SSH_STATUS == READY ]]; then
        echo 1
    else
        echo 0
    fi
}

# Wait for cloud-init finished.
wait_for_cloud_init () {
    SSH_STATUS=$(sudo ssh "${SSH_OPTIONS[@]}" -i "${SSH_KEY}" "${SSH_USER}@${1}" 'test -f /var/lib/cloud/instance/boot-finished && echo -n READY')
    if [[ $SSH_STATUS == READY ]]; then
        echo 1
    else
        echo 0
    fi
}

# Test result checking
check_result () {
    greenprint "Checking for test result"
    if [[ $RESULTS == 1 ]]; then
        greenprint "💚 Success"
    else
        greenprint "❌ Failed"
        clean_up
        exit 1
    fi
}

# Clean up our mess.
clean_up () {
    greenprint "🧼 Cleaning up"
    # Clear builder vm
    sudo virsh destroy "$BUILDER_VM_NAME"
    sudo virsh undefine "$BUILDER_VM_NAME" --nvram
    sudo virsh vol-delete --pool images "$GUEST_IMAGE_PATH"
    # Clear edge commit vm
    sudo virsh destroy "$EDGE_COMMIT_VM_NAME"
    sudo virsh undefine "$EDGE_COMMIT_VM_NAME" --nvram
    sudo virsh vol-delete --pool images "$EDGE_COMMIT_IMAGE_PATH"
    # Remove repo folder.
    sudo rm -rf "$COMMIT_HTTPD_PATH"
    # Remomve tmp dir.
    sudo rm -rf "$TEMPDIR"
}

# Variables before case
BOOT_ARGS="uefi"
EMBEDDED_CONTAINER="true"

# Set useful things according to different distros.
case "$TEST_OS" in
    "rhel-8-8")
        IMAGE_TYPE="edge-commit"
        sed -i "s/REPLACE_ME_HERE/${DOWNLOAD_NODE}/g" files/rhel-8-8-0.json
        cp tools/user-data.88 tools/user-data
        OS_VARIANT="rhel8-unknown"
        OSTREE_REF="rhel/8/${ARCH}/edge"
        GUEST_IMAGE_URL="http://${DOWNLOAD_NODE}/rhel-8/nightly/RHEL-8/latest-RHEL-8.8.0/compose/BaseOS/aarch64/images"
        GUEST_IMAGE_NAME=$(curl -s "${GUEST_IMAGE_URL}/" | grep -ioE ">rhel-guest-image-8.8-.*.qcow2<" | tr -d '><')
        USER_IN_COMMIT="true"
        BOOT_LOCATION="http://${DOWNLOAD_NODE}/rhel-8/nightly/RHEL-8/latest-RHEL-8.8.0/compose/BaseOS/aarch64/os/"
        ;;
    "rhel-9-2")
        IMAGE_TYPE="edge-commit"
        sed -i "s/REPLACE_ME_HERE/${DOWNLOAD_NODE}/g" files/rhel-8-8-0-sha512.json
        sed -i "s/REPLACE_ME_HERE/${DOWNLOAD_NODE}/g" files/rhel-9-1-0.json
        sed -i "s/REPLACE_ME_HERE/${DOWNLOAD_NODE}/g" files/rhel-9-2-0.json
        cp tools/user-data.92 tools/user-data
        OS_VARIANT="rhel9-unknown"
        OSTREE_REF="rhel/9/${ARCH}/edge"
        GUEST_IMAGE_URL="http://${DOWNLOAD_NODE}/rhel-9/nightly/RHEL-9/latest-RHEL-9.2.0/compose/BaseOS/aarch64/images"
        GUEST_IMAGE_NAME=$(curl -s "${GUEST_IMAGE_URL}/" | grep -ioE ">rhel-guest-image-9.2-.*.qcow2<" | tr -d '><')
        USER_IN_COMMIT="true"
        BOOT_LOCATION="http://${DOWNLOAD_NODE}/rhel-9/nightly/RHEL-9/latest-RHEL-9.2.0/compose/BaseOS/aarch64/os/"
        ;;
    "centos-stream-8")
        IMAGE_TYPE="edge-commit"
        OS_VARIANT="centos-stream8"
        OSTREE_REF="centos/8/${ARCH}/edge"
        GUEST_IMAGE_URL="https://cloud.centos.org/centos/8-stream/aarch64/images"
        GUEST_IMAGE_NAME=$(curl -s "${GUEST_IMAGE_URL}/" | grep -ioE ">CentOS-Stream-GenericCloud-8-.*.qcow2<" | tr -d '><' | tail -1)
        USER_IN_COMMIT="true"
        CURRENT_COMPOSE_CS8=$(curl -s "https://composes.centos.org/" | grep -ioE ">CentOS-Stream-8-.*/<" | tr -d '>/<' | tail -1)
        BOOT_LOCATION="https://composes.centos.org/${CURRENT_COMPOSE_CS8}/compose/BaseOS/aarch64/os/"
        ;;
    "centos-stream-9")
        IMAGE_TYPE="edge-commit"
        OS_VARIANT="centos-stream9"
        OSTREE_REF="centos/9/${ARCH}/edge"
        GUEST_IMAGE_URL="https://odcs.stream.centos.org/production/latest-CentOS-Stream/compose/BaseOS/aarch64/images"
        GUEST_IMAGE_NAME=$(curl -s "${GUEST_IMAGE_URL}/" | grep -ioE ">CentOS-Stream-GenericCloud-9-.*.qcow2<" | tr -d '><')
        USER_IN_COMMIT="true"
        CURRENT_COMPOSE_CS9=$(curl -s "https://composes.stream.centos.org/production/" | grep -ioE ">CentOS-Stream-9-.*/<" | tr -d '>/<' | tail -1)
        BOOT_LOCATION="https://composes.stream.centos.org/production/${CURRENT_COMPOSE_CS9}/compose/BaseOS/aarch64/os/"
        BOOT_ARGS="uefi,firmware.feature0.name=secure-boot,firmware.feature0.enabled=no"
        ;;
    "fedora-37")
        IMAGE_TYPE="fedora-iot-commit"
        OS_VARIANT="fedora-unknown"
        OSTREE_REF="fedora/37/${ARCH}/iot"
        GUEST_IMAGE_URL="https://download-cc-rdu01.fedoraproject.org/pub/fedora/linux/releases/37/Cloud/aarch64/images"
        GUEST_IMAGE_NAME=$(curl -s "${GUEST_IMAGE_URL}/" | grep -ioE ">Fedora-Cloud-Base-37-.*.qcow2<" | tr -d '><')
        USER_IN_COMMIT="false"
        EMBEDDED_CONTAINER="false"
        BOOT_LOCATION="https://download-cc-rdu01.fedoraproject.org/pub/fedora/linux/releases/37/Everything/aarch64/os/"
        ;;
    "fedora-38")
        IMAGE_TYPE="fedora-iot-commit"
        OS_VARIANT="fedora-unknown"
        OSTREE_REF="fedora/38/${ARCH}/iot"
        GUEST_IMAGE_URL="https://download-cc-rdu01.fedoraproject.org/pub/fedora/linux/development/rawhide/Cloud/aarch64/images"
        GUEST_IMAGE_NAME=$(curl -s "${GUEST_IMAGE_URL}/" | grep -ioE ">Fedora-Cloud-Base-Rawhide-.*.qcow2<" | tr -d '><')
        USER_IN_COMMIT="false"
        EMBEDDED_CONTAINER="false"
        BOOT_LOCATION="https://download-cc-rdu01.fedoraproject.org/pub/fedora/linux/development/rawhide/Everything/aarch64/os/"
        ;;
    *)
        echo "unsupported distro: ${ID}-${VERSION_ID}"
        exit 1;;
esac

# Set up variables.
TEMPDIR=$(mktemp -d)
LIBVIRT_IMAGE_PATH="/var/lib/libvirt/images"
COMMIT_HTTPD_PATH="/var/www/html/${TEST_OS}-commit"
BUILDER_VM_NAME="${TEST_OS}-commit-builder"
GUEST_IMAGE_PATH="${LIBVIRT_IMAGE_PATH}/guest-image-${TEST_OS}-commit.qcow2"
EDGE_COMMIT_VM_NAME="${TEST_OS}-commit"
EDGE_COMMIT_IMAGE_PATH="${LIBVIRT_IMAGE_PATH}/${TEST_OS}-commit.qcow2"
BLUEPRINT_FILE="${TEMPDIR}/blueprint.toml"
KS_FILE=${COMMIT_HTTPD_PATH}/ks.cfg
OS_NAME="rhel-edge"
PROD_REPO_ADDRESS=192.168.100.1
PROD_REPO_URL="http://${PROD_REPO_ADDRESS}/${TEST_OS}-commit/repo/"

# Download guest image
sudo curl --no-progress-meter -o "${GUEST_IMAGE_PATH}" "${GUEST_IMAGE_URL}/${GUEST_IMAGE_NAME}"
# Extend to 15G for image building required
sudo qemu-img resize "${GUEST_IMAGE_PATH}" 15G

# Prepare cloud-init data
CLOUD_INIT_DIR=$(mktemp -d)
cp tools/meta-data tools/user-data "$CLOUD_INIT_DIR"

# Set up a cloud-init ISO.
greenprint "💿 Creating a cloud-init ISO"
CLOUD_INIT_PATH="${LIBVIRT_IMAGE_PATH}/seed-commit.iso"
rm -f "$CLOUD_INIT_PATH"
pushd "$CLOUD_INIT_DIR"
    sudo mkisofs -o $CLOUD_INIT_PATH -V cidata \
        -r -J user-data meta-data > /dev/null 2>&1
popd
rm -rf "$CLOUD_INIT_DIR"

# Ensure SELinux is happy with image.
greenprint "👿 Running restorecon on image directory"
sudo restorecon -Rv /var/lib/libvirt/images/

# Import builder VM
sudo virt-install --name="$BUILDER_VM_NAME" \
                  --disk path="$GUEST_IMAGE_PATH",format=qcow2 \
                  --disk path="$CLOUD_INIT_PATH",device=cdrom \
                  --memory 2048 \
                  --vcpus 1 \
                  --network network=integration \
                  --os-variant "$OS_VARIANT" \
                  --boot uefi \
                  --import \
                  --noautoconsole \
                  --wait=-1 \
                  --noreboot

# Start VM.
greenprint "Start VM"
sudo virsh start "$BUILDER_VM_NAME"

# Wait until VM has IP addr from dhcp server
greenprint "Wait until VM's IP"
while ! sudo virsh domifaddr "$BUILDER_VM_NAME" | grep ipv4 > /dev/null;
do
    sleep 5
    echo "Booting..."
done

# Get VM IP address
greenprint "Get VM IP address"
BUILDER_VM_IP=$(sudo virsh domifaddr "$BUILDER_VM_NAME" | grep ipv4 | awk '{print $4}' | sed 's/\/24//')

# Check for ssh ready to go.
greenprint "🛃 Checking for SSH is ready to go"
for _ in $(seq 0 30); do
    RESULTS=$(wait_for_ssh_up "$BUILDER_VM_IP")
    if [[ $RESULTS == 1 ]]; then
        echo "SSH is ready now! 🥳"
        break
    fi
    sleep 10
done

# Wait for cloud-init finished.
greenprint "🛃 Wait for cloud-init finished"
for _ in $(seq 0 30); do
    RESULTS=$(wait_for_cloud_init "$BUILDER_VM_IP")
    if [[ $RESULTS == 1 ]]; then
        echo "Cloud-init finished! 🥳"
        break
    fi
    sleep 10
done

##################################################
##
## ostree image/commit installation
##
##################################################

# Write a blueprint for ostree image.
tee "$BLUEPRINT_FILE" > /dev/null << EOF
name = "ostree"
description = "A base ostree image"
version = "0.0.1"
modules = []
groups = []
[[packages]]
name = "python3"
version = "*"
[[packages]]
name = "sssd"
version = "*"
EOF

# Fedora does not support user configuration in blueprint for fedora-iot-commit image
if [[ "${USER_IN_COMMIT}" == "true" ]]; then
    tee -a "$BLUEPRINT_FILE" > /dev/null << EOF
[[customizations.user]]
name = "${SSH_USER}"
description = "Administrator account"
password = "\$6\$GRmb7S0p8vsYmXzH\$o0E020S.9JQGaHkszoog4ha4AQVs3sk8q0DvLjSMxoxHBKnB2FBXGQ/OkwZQfW/76ktHd0NX5nls2LPxPuUdl."
key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCzxo5dEcS+LDK/OFAfHo6740EyoDM8aYaCkBala0FnWfMMTOq7PQe04ahB0eFLS3IlQtK5bpgzxBdFGVqF6uT5z4hhaPjQec0G3+BD5Pxo6V+SxShKZo+ZNGU3HVrF9p2V7QH0YFQj5B8F6AicA3fYh2BVUFECTPuMpy5A52ufWu0r4xOFmbU7SIhRQRAQz2u4yjXqBsrpYptAvyzzoN4gjUhNnwOHSPsvFpWoBFkWmqn0ytgHg3Vv9DlHW+45P02QH1UFedXR2MqLnwRI30qqtaOkVS+9rE/dhnR+XPpHHG+hv2TgMDAuQ3IK7Ab5m/yCbN73cxFifH4LST0vVG3Jx45xn+GTeHHhfkAfBSCtya6191jixbqyovpRunCBKexI5cfRPtWOitM3m7Mq26r7LpobMM+oOLUm4p0KKNIthWcmK9tYwXWSuGGfUQ+Y8gt7E0G06ZGbCPHOrxJ8lYQqXsif04piONPA/c9Hq43O99KPNGShONCS9oPFdOLRT3U= ostree-image-test"
home = "/home/${SSH_USER}/"
groups = ["wheel"]
EOF
fi

# Fedora does not support embeded container in commit
if [[ "${EMBEDDED_CONTAINER}" == "true" ]]; then
    tee -a "$BLUEPRINT_FILE" > /dev/null << EOF
[[containers]]
source = "quay.io/fedora/fedora:latest"
EOF
fi

# Create inventory file
tee "${TEMPDIR}"/inventory > /dev/null << EOF
[builder]
${BUILDER_VM_IP}
[builder:vars]
ansible_python_interpreter=/usr/bin/python3
ansible_user=${SSH_USER}
ansible_private_key_file=${SSH_KEY}
ansible_ssh_common_args="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
EOF

# Build edge/iot-commit image
podman run -v "$(pwd)":/work:z -v "${TEMPDIR}":/tmp:z --rm quay.io/rhel-edge/ansible-runner:aarch64 ansible-playbook -v -i /tmp/inventory -e image_type="$IMAGE_TYPE" -e ostree_ref="$OSTREE_REF" build-image.yaml || RESULTS=0

# Copy image back from builder VM.
scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$SSH_KEY" "${SSH_USER}@${BUILDER_VM_IP}:/tmp/*-commit.tar" "${TEMPDIR}/edge-commit.tar"

# Remove image in builder VM
ssh "${SSH_OPTIONS[@]}" -i "${SSH_KEY}" "${SSH_USER}@${BUILDER_VM_IP}" 'rm -f /tmp/*.tar'

# Remove cloud-init ISO.
sudo rm -f "$CLOUD_INIT_PATH"

# Extract tar into ostree repo folder
sudo mkdir -p "$COMMIT_HTTPD_PATH"
sudo tar -xf "${TEMPDIR}/edge-commit.tar" -C "$COMMIT_HTTPD_PATH"
sudo rm -f "${TEMPDIR}/edge-commit.tar"

# Create qcow2 file for virt install.
greenprint "Create qcow2 file for virt install"
sudo qemu-img create -f qcow2 "${EDGE_COMMIT_IMAGE_PATH}" 20G

# Write kickstart file for ostree image installation.
greenprint "Generate kickstart file"
sudo tee "$KS_FILE" > /dev/null << STOPHERE
text
rootpw --lock --iscrypted locked
user --name=${SSH_USER} --groups=wheel --iscrypted --password=\$6\$1LgwKw9aOoAi/Zy9\$Pn3ErY1E8/yEanJ98evqKEW.DZp24HTuqXPJl6GYCm8uuobAmwxLv7rGCvTRZhxtcYdmC0.XnYRSR9Sh6de3p0
sshkey --username=${SSH_USER} "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCzxo5dEcS+LDK/OFAfHo6740EyoDM8aYaCkBala0FnWfMMTOq7PQe04ahB0eFLS3IlQtK5bpgzxBdFGVqF6uT5z4hhaPjQec0G3+BD5Pxo6V+SxShKZo+ZNGU3HVrF9p2V7QH0YFQj5B8F6AicA3fYh2BVUFECTPuMpy5A52ufWu0r4xOFmbU7SIhRQRAQz2u4yjXqBsrpYptAvyzzoN4gjUhNnwOHSPsvFpWoBFkWmqn0ytgHg3Vv9DlHW+45P02QH1UFedXR2MqLnwRI30qqtaOkVS+9rE/dhnR+XPpHHG+hv2TgMDAuQ3IK7Ab5m/yCbN73cxFifH4LST0vVG3Jx45xn+GTeHHhfkAfBSCtya6191jixbqyovpRunCBKexI5cfRPtWOitM3m7Mq26r7LpobMM+oOLUm4p0KKNIthWcmK9tYwXWSuGGfUQ+Y8gt7E0G06ZGbCPHOrxJ8lYQqXsif04piONPA/c9Hq43O99KPNGShONCS9oPFdOLRT3U= ostree-image-test"
network --bootproto=dhcp --device=link --activate --onboot=on
zerombr
clearpart --all --initlabel --disklabel=msdos
autopart --nohome --noswap --type=plain
ostreesetup --nogpg --osname=${OS_NAME} --remote=${OS_NAME} --url=${PROD_REPO_URL} --ref=${OSTREE_REF}
poweroff
%post --log=/var/log/anaconda/post-install.log --erroronfail
# no sudo password for SSH user
echo -e '${SSH_USER}\tALL=(ALL)\tNOPASSWD: ALL' >> /etc/sudoers
%end
STOPHERE

# Fedora does not support user configuration in blueprint for fedora-iot-commit image
if [[ "${USER_IN_COMMIT}" == "true" ]]; then
    sudo sed -i '/^user\|^sshkey/d' "${KS_FILE}"
fi

# Install ostree image via anaconda.
greenprint "Install ostree image via anaconda"
sudo virt-install  --initrd-inject="${KS_FILE}" \
                   --extra-args="inst.ks=file:/ks.cfg console=ttyS0,115200" \
                   --name="$EDGE_COMMIT_VM_NAME"\
                   --disk path="${EDGE_COMMIT_IMAGE_PATH}",format=qcow2 \
                   --ram 3072 \
                   --vcpus 2 \
                   --os-variant ${OS_VARIANT} \
                   --network network=integration \
                   --location "${BOOT_LOCATION}" \
                   --boot ${BOOT_ARGS} \
                   --nographics \
                   --noautoconsole \
                   --wait=-1 \
                   --noreboot

# Start VM.
greenprint "Start VM"
sudo virsh start "$EDGE_COMMIT_VM_NAME"

# Wait until VM has IP addr from dhcp server
greenprint "Wait until VM's IP"
while ! sudo virsh domifaddr "$EDGE_COMMIT_VM_NAME" | grep ipv4 > /dev/null;
do
    sleep 5
    echo "Booting..."
done

# Get VM IP address
greenprint "Get VM IP address"
EDGE_COMMIT_VM_IP=$(sudo virsh domifaddr "$EDGE_COMMIT_VM_NAME" | grep ipv4 | awk '{print $4}' | sed 's/\/24//')

# Check for ssh ready to go.
greenprint "🛃 Checking for SSH is ready to go"
for _ in $(seq 0 30); do
    RESULTS=$(wait_for_ssh_up "$EDGE_COMMIT_VM_IP")
    if [[ $RESULTS == 1 ]]; then
        echo "SSH is ready now! 🥳"
        break
    fi
    sleep 10
done

# Check image installation result
check_result

# Get ostree commit value.
greenprint "🕹 Get ostree commit value"
OSTREE_HASH=$(curl "${PROD_REPO_URL}refs/heads/${OSTREE_REF}")

# Add instance IP address into /etc/ansible/hosts
tee "${TEMPDIR}"/inventory > /dev/null << EOF
[ostree_guest]
${EDGE_COMMIT_VM_IP}
[ostree_guest:vars]
ansible_python_interpreter=/usr/bin/python3
ansible_user=${SSH_USER}
ansible_private_key_file=${SSH_KEY}
ansible_ssh_common_args="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
EOF

# Test IoT/Edge OS
podman run -v "$(pwd)":/work:z -v "${TEMPDIR}":/tmp:z --rm quay.io/rhel-edge/ansible-runner:aarch64 ansible-playbook -v -i /tmp/inventory -e os_name="${OS_NAME}" -e ostree_commit="${OSTREE_HASH}" -e ostree_ref="${OS_NAME}:${OSTREE_REF}" -e embedded_container="$EMBEDDED_CONTAINER" check-ostree.yaml || RESULTS=0
check_result

##################################################
##
## ostree image/commit upgrade
##
##################################################

# Write a blueprint for ostree image.
tee "$BLUEPRINT_FILE" > /dev/null << EOF
name = "upgrade"
description = "An upgrade ostree image"
version = "0.0.2"
modules = []
groups = []
[[packages]]
name = "python3"
version = "*"
[[packages]]
name = "wget"
version = "*"
[[packages]]
name = "sssd"
version = "*"
EOF

# Fedora does not support user configuration in blueprint for fedora-iot-commit image
if [[ "${USER_IN_COMMIT}" == "true" ]]; then
    tee -a "$BLUEPRINT_FILE" > /dev/null << EOF
[[customizations.user]]
name = "${SSH_USER}"
description = "Administrator account"
password = "\$6\$GRmb7S0p8vsYmXzH\$o0E020S.9JQGaHkszoog4ha4AQVs3sk8q0DvLjSMxoxHBKnB2FBXGQ/OkwZQfW/76ktHd0NX5nls2LPxPuUdl."
key = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCzxo5dEcS+LDK/OFAfHo6740EyoDM8aYaCkBala0FnWfMMTOq7PQe04ahB0eFLS3IlQtK5bpgzxBdFGVqF6uT5z4hhaPjQec0G3+BD5Pxo6V+SxShKZo+ZNGU3HVrF9p2V7QH0YFQj5B8F6AicA3fYh2BVUFECTPuMpy5A52ufWu0r4xOFmbU7SIhRQRAQz2u4yjXqBsrpYptAvyzzoN4gjUhNnwOHSPsvFpWoBFkWmqn0ytgHg3Vv9DlHW+45P02QH1UFedXR2MqLnwRI30qqtaOkVS+9rE/dhnR+XPpHHG+hv2TgMDAuQ3IK7Ab5m/yCbN73cxFifH4LST0vVG3Jx45xn+GTeHHhfkAfBSCtya6191jixbqyovpRunCBKexI5cfRPtWOitM3m7Mq26r7LpobMM+oOLUm4p0KKNIthWcmK9tYwXWSuGGfUQ+Y8gt7E0G06ZGbCPHOrxJ8lYQqXsif04piONPA/c9Hq43O99KPNGShONCS9oPFdOLRT3U= ostree-image-test"
home = "/home/${SSH_USER}/"
groups = ["wheel"]
EOF
fi

# Fedora does not support embeded container in commit
if [[ "${EMBEDDED_CONTAINER}" == "true" ]]; then
    tee -a "$BLUEPRINT_FILE" > /dev/null << EOF
[[containers]]
source = "quay.io/fedora/fedora:latest"
EOF
fi

# Create inventory file
tee "${TEMPDIR}"/inventory > /dev/null << EOF
[builder]
${BUILDER_VM_IP}
[builder:vars]
ansible_python_interpreter=/usr/bin/python3
ansible_user=${SSH_USER}
ansible_private_key_file=${SSH_KEY}
ansible_ssh_common_args="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
EOF

# Build edge/iot-commit upgrade image
podman run -v "$(pwd)":/work:z -v "${TEMPDIR}":/tmp:z --rm quay.io/rhel-edge/ansible-runner:aarch64 ansible-playbook -v -i /tmp/inventory -e image_type="$IMAGE_TYPE" -e upgrade="true" -e ostree_ref="$OSTREE_REF" -e repo_url="$PROD_REPO_URL" build-image.yaml || RESULTS=0

# Copy image back from builder VM.
scp -q -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "$SSH_KEY" "${SSH_USER}@${BUILDER_VM_IP}:/tmp/*-commit.tar" "${TEMPDIR}/edge-commit.tar"

# Remove image in builder VM
ssh "${SSH_OPTIONS[@]}" -i "${SSH_KEY}" "${SSH_USER}@${BUILDER_VM_IP}" 'rm -f /tmp/*.tar'

# Extract upgrade repo
UPGRADE_PATH="${TEMPDIR}/upgrade"
mkdir -p "$UPGRADE_PATH"
sudo tar -xf "${TEMPDIR}/edge-commit.tar" -C "$UPGRADE_PATH"
sudo rm -f "${TEMPDIR}/edge-commit.tar"

# Introduce new ostree commit into repo.
greenprint "Introduce new ostree commit into repo"
sudo ostree pull-local --repo "${COMMIT_HTTPD_PATH}/repo" "${UPGRADE_PATH}/repo" "$OSTREE_REF"
sudo ostree summary --update --repo "${COMMIT_HTTPD_PATH}/repo"

# Remove upgrade repo
sudo rm -rf "$UPGRADE_PATH"

# Get upgrade commit value.
greenprint "🕹 Get ostree upgrade commit value"
UPGRADE_HASH=$(curl "${PROD_REPO_URL}refs/heads/${OSTREE_REF}")

# Upgrade image/commit.
greenprint "Upgrade ostree image/commit"
sudo ssh "${SSH_OPTIONS[@]}" -i "${SSH_KEY}" "${SSH_USER}@${EDGE_COMMIT_VM_IP}" 'sudo rpm-ostree upgrade'
sudo ssh "${SSH_OPTIONS[@]}" -i "${SSH_KEY}" "${SSH_USER}@${EDGE_COMMIT_VM_IP}" 'nohup sudo systemctl reboot &>/dev/null & exit'

# Sleep 10 seconds here to make sure vm restarted already
sleep 10

# Check for ssh ready to go.
greenprint "🛃 Checking for SSH is ready to go"
# shellcheck disable=SC2034  # Unused variables left for readability
for _ in $(seq 0 30); do
    RESULTS=$(wait_for_ssh_up "$EDGE_COMMIT_VM_IP")
    if [[ $RESULTS == 1 ]]; then
        echo "SSH is ready now! 🥳"
        break
    fi
    sleep 10
done

# Check ostree upgrade result
check_result

# Add instance IP address into /etc/ansible/hosts
tee "${TEMPDIR}"/inventory > /dev/null << EOF
[ostree_guest]
${EDGE_COMMIT_VM_IP}
[ostree_guest:vars]
ansible_python_interpreter=/usr/bin/python3
ansible_user=${SSH_USER}
ansible_private_key_file=${SSH_KEY}
ansible_ssh_common_args="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
EOF

# Test IoT/Edge OS
podman run -v "$(pwd)":/work:z -v "${TEMPDIR}":/tmp:z --rm quay.io/rhel-edge/ansible-runner:aarch64 ansible-playbook -v -i /tmp/inventory -e os_name="${OS_NAME}" -e ostree_commit="${UPGRADE_HASH}" -e ostree_ref="${OS_NAME}:${OSTREE_REF}" -e embedded_container="$EMBEDDED_CONTAINER" check-ostree.yaml || RESULTS=0
check_result

# Final success clean up
clean_up

exit 0
