/* Copyright 2019 IBM Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
 * implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <timebase.h>
#include <skiboot.h>
#include <device.h>
#include "../status_codes.h"
#include "../tpm_chip.h"
#include "tpm_tis.h"
#include <io.h>
#include <lpc.h>
#include <opal-api.h>

#define DBG(fmt, ...) prlog(PR_ERR, fmt, ##__VA_ARGS__)
//#define DBG(fmt, ...)

#define DRIVER_NAME "tpm_tis"

/*
 * Timings between various states or transitions within the interface protocol
 * as defined in the TCG PC Client Platform TPM Profile specification, Revision
 * 00.43.
 */
#define TPM_TIMEOUT_A	750
#define TPM_TIMEOUT_B	2000
#define TPM_TIMEOUT_D	30

/* TIS interface offsets */
#define TPM_STS			0x18
#define TPM_DATA_FIFO		0x24

/* Bit masks for the TPM STATUS register */
#define TPM_STS_VALID		0x80
#define TPM_STS_COMMAND_READY	0x40
#define TPM_STS_GO		0x20
#define TPM_STS_DATA_AVAIL	0x10
#define TPM_STS_EXPECT		0x08


/* TPM Driver values */
#define MAX_STSVALID_POLLS 	5
#define TPM_TIMEOUT_INTERVAL	10

static struct tpm_dev *tpm_device = NULL;
#define base 0

static int tpm_status_write_byte(uint8_t byte)
{
	return lpc_write(OPAL_LPC_MEM, base + TPM_STS, byte, 1);
}

static int tpm_status_read_byte(uint8_t *byte)
{
	uint32_t buffer;
	int rc;
	rc = lpc_read(OPAL_LPC_MEM, base + TPM_STS, &buffer, 1);
	*byte = (uint8_t)buffer;
	return rc;
}

static bool tpm_check_status(uint8_t status, uint8_t mask, uint8_t expected)
{
	return ((status & mask) == expected);
}

static int tpm_wait_for_command_ready(void)
{
	uint64_t start, stop, now;
	int rc;
	uint8_t status;

	start = mftb();
	stop = start + msecs_to_tb(TPM_TIMEOUT_B);

	do {
		now = mftb();
		rc = tpm_status_read_byte(&status);
		if (rc < 0) {
			/**
			 * @fwts-label TPMReadCmdReady
			 * @fwts-advice Either the tpm device or the tpm-i2c
			 * interface doesn't seem to be working properly. Check
			 * the return code (rc) for further details.
			 */
			prlog(PR_ERR, "TPM_TIS: fail to read sts.commandReady, "
			      "rc=%d\n", rc);
			return STB_DRIVER_ERROR;
		}
		if (tpm_check_status(status,
				     TPM_STS_COMMAND_READY,
				     TPM_STS_COMMAND_READY)) {
			DBG("--- Command ready, delay=%lu/%d\n",
			    tb_to_msecs(now-start), TPM_TIMEOUT_B);
			return 0;
		}
		if (tb_compare(now, stop) == TB_ABEFOREB)
			time_wait_ms(TPM_TIMEOUT_INTERVAL);
		else
			break;
	} while (1);

	return STB_TPM_TIMEOUT;
}

static int tpm_set_command_ready(void)
{
	int rc, retries;
	/*
	 * The first write to command ready may just abort an
	 * outstanding command, so we poll twice
	 */
	for (retries = 0; retries < 2; retries++) {
		rc = tpm_status_write_byte(TPM_STS_COMMAND_READY);
		if (rc < 0) {
			/**
			 * @fwts-label TPMWriteCmdReady
			 * @fwts-advice Either the tpm device or the tpm-tis
			 * interface doesn't seem to be working properly. Check
			 * the return code (rc) for further details.
			 */
			prlog(PR_ERR, "TPM_TIS: fail to write sts.commandReady, "
			      "rc=%d\n", rc);
			return STB_DRIVER_ERROR;
		}
		rc = tpm_wait_for_command_ready();
		if (rc == STB_TPM_TIMEOUT)
			continue;
		return rc;
	}
	/**
	 * @fwts-label TPMCmdReadyTimeout
	 * @fwts-advice The command ready bit of the tpm status register is
	 * taking longer to be settled. Either the wait time need to be
	 * increased or the TPM device is not functional.
	 */
	prlog(PR_ERR, "TPM_TIS: timeout on sts.commandReady, delay > %d\n",
	      2*TPM_TIMEOUT_B);
	return STB_TPM_TIMEOUT;
}

static int tpm_wait_for_fifo_status(uint8_t mask, uint8_t expected)
{
	int retries, rc;
	uint8_t status;

	for(retries = 0; retries <= MAX_STSVALID_POLLS; retries++) {
		rc = tpm_status_read_byte(&status);
		if (rc < 0) {
			/**
			 * @fwts-label TPMReadFifoStatus
			 * @fwts-advice Either the tpm device or the tpm-i2c
			 * interface doesn't seem to be working properly. Check
			 * the return code (rc) for further details.
			 */
			prlog(PR_ERR, "TPM_TIS: fail to read fifo status: "
			      "mask %x, expected %x, rc=%d\n", mask, expected,
			      rc);
			return STB_DRIVER_ERROR;
		}
		if (tpm_check_status(status, mask, expected))
			return 0;
		/* Wait TPM STS register be settled */
		time_wait_ms(5);
	}
	return STB_TPM_TIMEOUT;
}

static int tpm_wait_for_data_avail(void)
{
	uint64_t start, stop, now;
	uint8_t status;
	int rc;

	start = mftb();
	stop = start + msecs_to_tb(TPM_TIMEOUT_A);

	do {
		now = mftb();
		rc = tpm_status_read_byte(&status);
		if (rc < 0) {
			/**
			 * @fwts-label TPMReadDataAvail
			 * @fwts-advice Either the tpm device or the tpm-i2c
			 * interface doesn't seem to be working properly. Check
			 * the return code (rc) for further details.
			 */
			prlog(PR_ERR, "TPM_TIS: fail to read sts.dataAvail, "
			      "rc=%d\n", rc);
			return STB_DRIVER_ERROR;
		}
		if (tpm_check_status(status,
				     TPM_STS_VALID | TPM_STS_DATA_AVAIL,
				     TPM_STS_VALID | TPM_STS_DATA_AVAIL)) {
			DBG("---- Data available. delay=%lu/%d\n",
			    tb_to_msecs(now-start), TPM_TIMEOUT_A);
			return 0;
		}
		if (tb_compare(now, stop) == TB_ABEFOREB)
			time_wait_ms(TPM_TIMEOUT_INTERVAL);
		else
			break;
	} while (1);
	/**
	 * @fwts-label TPMDataAvailBitTimeout
	 * @fwts-advice The data avail bit of the tpm status register is taking
	 * longer to be settled. Either the wait time need to be increased or
	 * the TPM device is not functional.
	 */
	prlog(PR_ERR, "TPM_TIS: timeout on sts.dataAvail, delay=%lu/%d\n",
	      tb_to_msecs(now-start), TPM_TIMEOUT_A);
	return STB_TPM_TIMEOUT;
}

static int tpm_write_fifo(uint8_t* buf, size_t buflen)
{
	int rc;
	size_t count, bytes;

	/*
	 * We will transfer the command except for the last byte
	 * that will be transfered separately to allow for
	 * overflow checking
	 */
	count = 0;
	do {
		bytes = 1;

		rc = lpc_write(OPAL_LPC_MEM, TPM_DATA_FIFO, (uint32_t)buf[count], 1);
		count += bytes;
		DBG("%s FIFO: %zd bytes written, count=%zd, rc=%d\n",
		    (rc) ? "!!!!" : "----", bytes, count, rc);
		if (rc < 0) {
			/**
			 * @fwts-label TPMWriteFifo
			 * @fwts-advice Either the tpm device or the tpm-i2c
			 * interface doesn't seem to be working properly. Check
			 * the return code (rc) for further details.
			 */
			prlog(PR_ERR, "TPM_TIS: fail to write fifo, "
			      "count=%zd, rc=%d\n", count, rc);
			return STB_DRIVER_ERROR;
		}

		rc = tpm_wait_for_fifo_status(TPM_STS_VALID | TPM_STS_EXPECT,
					      TPM_STS_VALID | TPM_STS_EXPECT);
		if (rc == STB_DRIVER_ERROR)
			return rc;
		if (rc == STB_TPM_TIMEOUT) {
			/**
			 * @fwts-label TPMWriteFifoNotExpecting
			 * @fwts-advice The write to the TPM FIFO overflowed,
			 * the TPM is not expecting more data. This indicates a
			 * bug in the TPM device driver.
			 */
			prlog(PR_ERR, "TPM_TIS: write FIFO overflow, not expecting "
			      "more data\n");
			return STB_TPM_OVERFLOW;
		}
	} while (count < buflen - 1);

	/*
	 *  Write the last byte
	 */
	rc = lpc_write(OPAL_LPC_MEM, TPM_DATA_FIFO, (uint32_t)buf[count], 1);
	count++;
	DBG("%s FIFO: last byte written, count=%zd, rc=%d\n",
	    (rc) ? "!!!!" : "----", count, rc);

	if (rc < 0) {
		/**
		 * @fwts-label TPMWriteFifoLastByte
		 * @fwts-advice Either the tpm device or the tpm-i2c interface
		 * doesn't seem to be working properly. Check the return code
		 * (rc) for further details.
		 */
		prlog(PR_ERR, "TPM_TIS: fail to write fifo (last byte), "
		      "count=%zd, rc=%d\n", count, rc);
		return STB_DRIVER_ERROR;
	}
	rc = tpm_wait_for_fifo_status(TPM_STS_VALID | TPM_STS_EXPECT,
				      TPM_STS_VALID | TPM_STS_EXPECT);
	if (rc == STB_DRIVER_ERROR)
		return rc;
	if (rc == 0) {
		 /**
		 * @fwts-label TPMWriteFifoExpecting
		 * @fwts-advice The write to the TPM FIFO overflowed.
		 * It is expecting more data even though we think we
		 * are done. This indicates a bug in the TPM device
		 * driver.
		 */
		prlog(PR_ERR, "TPM: write FIFO overflow, expecting "
		      "more data\n");
		return STB_TPM_OVERFLOW;
	}
	return 0;
}

static int tpm_read_fifo(uint8_t* buf, size_t* buflen)
{
	int rc;
	size_t count;
	uint32_t bounce_buffer;

	rc = tpm_wait_for_data_avail();
	if (rc < 0)
		goto error;

	count = 0;
	do {
		rc = lpc_read(OPAL_LPC_MEM, TPM_DATA_FIFO, &bounce_buffer, 1);
		buf[count] = (uint8_t)bounce_buffer;
		count++;
		DBG("%s FIFO: byte read, count=%zd, rc=%d\n",
		    (rc) ? "!!!!" : "----", count, rc);
		if (rc < 0) {
			/**
			 * @fwts-label TPMReadFifo
			 * @fwts-advice Either the tpm device or the tpm-i2c interface
			 * doesn't seem to be working properly. Check the return code
			 * (rc) for further details.
			 */
			prlog(PR_ERR, "TPM_TIS: fail to read fifo, count=%zd, "
			      "rc=%d\n", count, rc);
			rc = STB_DRIVER_ERROR;
			goto error;
		}
		rc = tpm_wait_for_fifo_status(
					  TPM_STS_VALID | TPM_STS_DATA_AVAIL,
					  TPM_STS_VALID | TPM_STS_DATA_AVAIL);
		if (rc == STB_DRIVER_ERROR)
			goto error;
	} while (rc == 0);

	*buflen = count;
	return 0;

error:
	*buflen = 0;
	return rc;
}

static int tpm_transmit(struct tpm_dev *dev, uint8_t* buf, size_t cmdlen,
			size_t* buflen)
{
	int rc = 0;
	if (!dev) {
		/**
		 * @fwts-label TPMDeviceNotInitialized
		 * @fwts-advice TPM device is not initialized. This indicates a
		 * bug in the tpm_transmit() caller
		 */
		prlog(PR_ERR, "TPM: tpm device not initialized\n");
		return STB_ARG_ERROR;
	}
	tpm_device = dev;
	DBG("**** %s: dev %#x/%#x buf %016llx cmdlen %zu"
	    " buflen %zu ****\n",
	    __func__, dev->bus_id, dev->i2c_addr, *(uint64_t *) buf,
	    cmdlen, *buflen);

	DBG("step 1/5: set command ready\n");
	rc = tpm_set_command_ready();
	if (rc < 0)
		goto out;

	DBG("step 2/5: write FIFO\n");
	rc = tpm_write_fifo(buf, cmdlen);
	if (rc < 0)
		goto out;

	DBG("step 3/5: write sts.go\n");
	rc = tpm_status_write_byte(TPM_STS_GO);
	if (rc < 0) {
		/**
		 * @fwts-label TPMWriteGo
		 * @fwts-advice Either the tpm device or the tpm-i2c interface
		 * doesn't seem to be working properly. Check the return code
		 * (rc) for further details.
		 */
		prlog(PR_ERR, "TPM_TIS: fail to write sts.go, rc=%d\n", rc);
		rc = STB_DRIVER_ERROR;
		goto out;
	}

	DBG("step 4/5: read FIFO\n");
	rc = tpm_read_fifo(buf, buflen);
	if (rc < 0)
		goto out;

	DBG("step 5/5: release tpm\n");
	rc = tpm_status_write_byte(TPM_STS_COMMAND_READY);
	if (rc < 0) {
		/**
		 * @fwts-label TPMReleaseTpm
		 * @fwts-advice Either the tpm device or the tpm-i2c interface
		 * doesn't seem to be working properly. Check the return code
		 * (rc) for further details.
		 */
		prlog(PR_ERR, "TPM_TIS: fail to release tpm, rc=%d\n", rc);
		rc = STB_DRIVER_ERROR;
	}

out:
	DBG("**** tpm_transmit %s, rc=%d ****\n",
	    (rc) ? "ERROR" : "SUCCESS", rc);
	return rc;
}

static struct tpm_driver tpm_tis_driver = {
	.name     = DRIVER_NAME,
	.transmit = tpm_transmit,
};

#define TPM_TIS_ADDR_BASE 0xfed40000
#include <lpc.h>
void tpm_tis_probe(void)
{
	struct tpm_dev *tpm_device = NULL;
	struct dt_node *node = NULL;

	prlog(PR_ERR, "TPM: tis probe\n");
	dt_for_each_compatible(dt_root, node, "tcg,tpm-tis-mmio") {
		if (!dt_node_is_enabled(node))
			continue;
		tpm_device = (struct tpm_dev*) malloc(sizeof(struct tpm_dev));
		assert(tpm_device);

		/*
		 * Read TPM device address and bus id. Make sure the properties
		 * really exist if the default value is returned.
		 */
		tpm_device->i2c_addr = dt_prop_get_u32_def(node, "reg", 0);
		if (!tpm_device->i2c_addr && !dt_find_property(node, "reg")) {
			/*
			 * @fwts-label TPM_TISRegNotFound
			 * @fwts-advice reg property not found. This indicates
			 * a Hostboot bug if the property really doesn't exist
			 * in the tpm node.
			 */
			prlog(PR_ERR, "TPM_TIS: reg property not found, "
			      "tpm node %p\n", node);
			goto disable;
		}
		lpc_write(OPAL_LPC_MEM, 0, 2, 1); // activate loc 0?

		if (tpm_register_chip(node, tpm_device,
				      &tpm_tis_driver)) {
			free(tpm_device);
			continue;
		}
	}
	return;
disable:
	dt_add_property_string(node, "status", "disabled");
	prlog(PR_NOTICE, "TPM: tpm node %p disabled\n", node);
	free(tpm_device);
}
