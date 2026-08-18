# Fixtures de `df` — deduplicado por sistema de ficheros

Alimentan `test/manual/test-disk-dedupe.js`, que comprueba que
`disk-storage.js` emite **una entrada por sistema de ficheros** y no una por
punto de montaje (ver el problema de los subvolúmenes btrfs).

| Fichero | Comando | Procedencia |
|---|---|---|
| `macos-apfs-real.txt` | `df -k` | **Real.** Capturado en el MacBook de desarrollo (APFS). Es el caso de no-regresión: cada volumen APFS tiene su propio `/dev/diskXsY`, así que el deduplicado no debe cambiar nada. |
| `linux-btrfs-real-container.txt` | `df -kPT` | **Real.** btrfs de verdad creado en un contenedor `debian:12 --privileged`: imagen de 2 GB, `mkfs.btrfs`, 7 subvolúmenes (`@ @home @root @srv @cache @log @tmp`) montados a la vez, más un ext4 y un vfat de verdad. Demuestra que `df` repite la MISMA fila (mismo `/dev/loop0`, mismas cifras) una vez por subvolumen. |
| `linux-btrfs-cachyos.txt` | `df -kPT` | **Derivado** del anterior: mismas cifras y estructura, con los puntos de montaje y nombres de dispositivo de una instalación CachyOS normal (`/dev/nvme0n1p2`, `/`, `/home`, `/var/log`…) y los `tmpfs` que trae systemd. Reproduce el recuento inflado que se vio en el dashboard. |
| `linux-btrfs-busybox-notype.txt` | `df -kP` | **Derivado.** Sin columna `Type`: cubre la ruta de degradación cuando `df -T` no existe (busybox/toybox). El deduplicado por dispositivo debe seguir funcionando. |
| `linux-zfs.txt` | `df -kPT` | **Sintético.** No se pudo generar ZFS real: el kernel de Docker Desktop (`6.12.54-linuxkit`) no trae el módulo `zfs`. Escrito siguiendo la semántica documentada de OpenZFS: cada dataset es un "filesystem" distinto pero todos comparten el `Available` del pool. Incluye dos pools (`rpool`, `tank`) para comprobar que no se mezclan. |
