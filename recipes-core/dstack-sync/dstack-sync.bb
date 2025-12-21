DESCRIPTION = "Syncs the date and time of the VM periodically using BusyBox ntpd"
LICENSE = "CLOSED"
FILESEXTRAPATHS:prepend := "${THISDIR}:"

BINARY = "mini-server"

SRC_URI += "file://init"
SRC_URI += "file://${BINARY}"

INITSCRIPT_NAME = "dstack-sync"
INITSCRIPT_PARAMS = "defaults 80"

inherit update-rc.d

do_install() {
    install -d ${D}${sysconfdir}/init.d
    install -m 0755 ${WORKDIR}/init ${D}${sysconfdir}/init.d/dstack-sync
    install -d ${D}${bindir}
    install -m 0777 ${WORKDIR}/${BINARY} ${D}${bindir}
}
