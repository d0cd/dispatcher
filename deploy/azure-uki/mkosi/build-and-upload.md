# Build the measured Azure CVM image (validated flow)

Reproduces the live-validated build. All on a Linux builder + `az` locally.

## 1. Builder + mkosi (from git — apt's 20.2 and PyPI don't work on noble)

```
pipx install git+https://github.com/systemd/mkosi.git
sudo apt-get install -y systemd-boot-efi mtools qemu-utils   # host tools mkosi needs
```

Put the cross-compiled `dispatcher-attest-azuresnp` in `mkosi.extra/usr/local/bin/`
+ its enabled systemd unit, then `sudo mkosi --force build` -> `azurecvm.raw`.

## 2. raw -> fixed VHD (1 MiB aligned)

```
truncate -s $(( (SZ+1048575)/1048576*1048576 )) azurecvm.raw
qemu-img convert -f raw -O vpc -o subformat=fixed,force_size azurecvm.raw azurecvm.vhd
```

## 3. Upload as a VHD blob (ConfidentialVM needs a blob source, NOT a managed disk)

```
az provider register --namespace Microsoft.Storage    # if not registered
az storage account create -g RG -n <sa> -l eastus --sku Standard_LRS
az storage container create --account-name <sa> --account-key <k> -n vhds
azcopy copy azurecvm.vhd "<container-SAS>/azurecvm.vhd" --blob-type PageBlob
```

## 4. Gallery image (ConfidentialVmSupported) from the blob

```
az sig create -g RG --gallery-name dispgal
az sig image-definition create -g RG --gallery-name dispgal --gallery-image-definition azuresnp \
  --publisher dispatcher --offer measured --sku noble --os-type Linux --hyper-v-generation V2 \
  --features SecurityType=ConfidentialVmSupported
az sig image-version create -g RG --gallery-name dispgal --gallery-image-definition azuresnp \
  --gallery-image-version 1.0.0 --os-vhd-uri "https://<sa>.blob.core.windows.net/vhds/azurecvm.vhd" \
  --os-vhd-storage-account <sa-id>
```

## 5. Boot the CVM — use an ARM template, NOT `az vm create`

`az vm create` from a custom gallery image trips an az-CLI bug (2.88 on Python
3.14: "content already consumed"). An ARM `deployment group create` works. The VM
resource needs `securityProfile.securityType=ConfidentialVM`,
`uefiSettings.vTpmEnabled=true`, `secureBootEnabled=false`, and the osDisk
`managedDisk.securityProfile.securityEncryptionType=VMGuestStateOnly`.

## 6. Attest

The agent auto-starts; fetch `/attest`, read PCR11, pin `DISPATCHER_AZURE_SNP_PCR11`.
`TestGolden_AzureSNPLiveExchange` verifies the full loop.
