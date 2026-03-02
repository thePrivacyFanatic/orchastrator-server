#!/bin/bash
podman stop orchastrator-server
podman container rm orchastrator-server
podman image rm orchastrator-server
podman build . -t orchastrator-server
podman run --volume ~/.local/share/containers/storage/volumes/orchastratorDB/_data:/usr/src/app/db --name orchastrator-server --publish 9000:443 orchastrator-server
