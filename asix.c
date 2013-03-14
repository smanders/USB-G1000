/*
 * ASIX AX8817X based USB 2.0 Ethernet Devices
 * Copyright (C) 2003-2005 David Hollis <dhollis@davehollis.com>
 * Copyright (C) 2005 Phil Chang <pchang23@sbcglobal.net>
 * Copyright (c) 2002-2003 TiVo Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#define	DEBUG			// error path messages, extra info
#define	VERBOSE			// more; success messages

#include <linux/version.h>
//#include <linux/config.h>
#ifdef	CONFIG_USB_DEBUG
#   define DEBUG
#endif
#include <linux/module.h>
#include <linux/kmod.h>
#include <linux/sched.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/etherdevice.h>
#include <linux/ethtool.h>
#include <linux/workqueue.h>
#include <linux/mii.h>
#include <linux/usb.h>
#include <linux/crc32.h>

#include "asix.h"
//#include "usbnet.h"
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
#include <../drivers/usb/net/usbnet.h>
#else
# if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,25)
#include <../drivers/net/usb/usbnet.h>
#else
#include <linux/usb/usbnet.h>
#endif
#endif

#define DRV_VERSION	"3.2.0"

static char version[] =
KERN_INFO "ASIX USB Ethernet Adapter:v" DRV_VERSION 
	" " __TIME__ " " __DATE__ "\n"
KERN_INFO "    http://www.asix.com.tw";

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static void ax88772b_link_reset (void *data);
static void ax88772a_link_reset (void *data);
static void ax88772_link_reset (void *data);
#else
static void ax88772b_link_reset (struct work_struct *work);
static void ax88772a_link_reset (struct work_struct *work);
static void ax88772_link_reset (struct work_struct *work);
#endif
static int ax88772a_phy_powerup (struct usbnet *dev);

/* ASIX AX8817X based USB 2.0 Ethernet Devices */

static int ax8817x_read_cmd(struct usbnet *dev, u8 cmd, u16 value, u16 index,
			    u16 size, void *data)
{
	return usb_control_msg(
		dev->udev,
		usb_rcvctrlpipe(dev->udev, 0),
		cmd,
		USB_DIR_IN | USB_TYPE_VENDOR | USB_RECIP_DEVICE,
		value,
		index,
		data,
		size,
		USB_CTRL_GET_TIMEOUT);
}

static int ax8817x_write_cmd(struct usbnet *dev, u8 cmd, u16 value, u16 index,
			     u16 size, void *data)
{
	return usb_control_msg(
		dev->udev,
		usb_sndctrlpipe(dev->udev, 0),
		cmd,
		USB_DIR_OUT | USB_TYPE_VENDOR | USB_RECIP_DEVICE,
		value,
		index,
		data,
		size,
		USB_CTRL_SET_TIMEOUT);
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static void ax8817x_async_cmd_callback(struct urb *urb, struct pt_regs *regs)
#else
static void ax8817x_async_cmd_callback(struct urb *urb)
#endif
{
	struct usb_ctrlrequest *req = (struct usb_ctrlrequest *)urb->context;

	if (urb->status < 0)
		printk(KERN_DEBUG "ax8817x_async_cmd_callback() failed with %d",
			urb->status);

	kfree(req);
	usb_free_urb(urb);
}

static int ax8817x_set_mac_addr (struct net_device *net, void *p)
{
	struct usbnet *dev = netdev_priv(net);
	struct sockaddr *addr = p;

	memcpy (net->dev_addr, addr->sa_data, ETH_ALEN);

	/* Set the MAC address */
	return ax8817x_write_cmd (dev, AX88772_CMD_WRITE_NODE_ID,
			   0, 0, ETH_ALEN, net->dev_addr);

}

static void ax88178_status(struct usbnet *dev, struct urb *urb)
{
	struct ax88172_int_data *event;
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	struct ax88178_data *ax178dataptr = data->priv.ax178dataptr;
	int link;

	if (urb->actual_length < 8)
		return;

	if (ax178dataptr->EepromData == 0x7C)
		return;

	event = urb->transfer_buffer;
	link = event->link & 0x01;
	if (netif_carrier_ok(dev->net) != link) {
		if (link) {
			netif_carrier_on(dev->net);
			usbnet_defer_kevent (dev, EVENT_LINK_RESET );
		} else
			netif_carrier_off(dev->net);
		netdev_warn(dev->net, "ax8817x - Link Status is: %d", link);
	}
}

static void ax8817x_status(struct usbnet *dev, struct urb *urb)
{
	struct ax88172_int_data *event;
	int link;

	if (urb->actual_length < 8)
		return;

	event = urb->transfer_buffer;
	link = event->link & 0x01;
	if (netif_carrier_ok(dev->net) != link) {
		if (link) {
			netif_carrier_on(dev->net);
			usbnet_defer_kevent (dev, EVENT_LINK_RESET );
		} else
			netif_carrier_off(dev->net);
		netdev_warn(dev->net, "ax8817x - Link Status is: %d", link);
	}
}

static void ax88772_status(struct usbnet *dev, struct urb *urb)
{
	struct ax88172_int_data *event;
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	struct ax88772_data *ax772_data = data->priv.ax772_data;
	int link;
	
	if (urb->actual_length < 8)
		return;

	event = urb->transfer_buffer;
	link = event->link & 0x01;
	
	if (netif_carrier_ok(dev->net) != link) {
		if (link) {
			netif_carrier_on(dev->net);
			ax772_data->Event = AX_SET_RX_CFG;
		} else {
			netif_carrier_off(dev->net);
			if (ax772_data->Event == AX_NOP) {
				ax772_data->Event = PHY_POWER_DOWN;
				ax772_data->TickToExpire = 25;
			}
		}

		netdev_warn(dev->net, "ax8817x - Link Status is: %d", link);
	}
	
	if (ax772_data->Event)
		queue_work (ax772_data->ax_work, &ax772_data->check_link);
}

static void ax88772a_status(struct usbnet *dev, struct urb *urb)
{
	struct ax88172_int_data *event;
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	struct ax88772a_data *ax772a_data = data->priv.ax772a_data;
	int link;
	int PowSave = (ax772a_data->EepromData >> 14);

	if (urb->actual_length < 8)
		return;

	event = urb->transfer_buffer;
	link = event->link & 0x01;

	if (netif_carrier_ok(dev->net) != link) {

		if (link) {
			netif_carrier_on(dev->net);
			ax772a_data->Event = AX_SET_RX_CFG;
		} else if ((PowSave == 0x3) || (PowSave == 0x1)) {
			netif_carrier_off(dev->net);
			if (ax772a_data->Event == AX_NOP) {
				ax772a_data->Event = CHK_CABLE_EXIST;
				ax772a_data->TickToExpire = 14;
			}
		} else {
			netif_carrier_off(dev->net);
			ax772a_data->Event = AX_NOP;
		}

		netdev_warn(dev->net, "ax8817x - Link Status is: %d", link);
	}
	
	if (ax772a_data->Event)
		queue_work (ax772a_data->ax_work, &ax772a_data->check_link);
}

static void ax88772b_status(struct usbnet *dev, struct urb *urb)
{
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	struct ax88772b_data *ax772b_data = data->priv.ax772b_data;
	struct ax88172_int_data *event;
	int link;

	if (urb->actual_length < 8)
		return;

	event = urb->transfer_buffer;
	link = event->link & AX_INT_PPLS_LINK;
	if (netif_carrier_ok(dev->net) != link) {
		if (link) {
			netif_carrier_on(dev->net);
			ax772b_data->Event = AX_SET_RX_CFG;
		} else {
			netif_carrier_off(dev->net);
			ax772b_data->time_to_chk = jiffies;
		}
		netdev_warn(dev->net, "ax8817x - Link Status is: %d", link);
	}

	if (!link) {

		int no_cable = (event->link & AX_INT_CABOFF_UNPLUG) ? 1 : 0;

		if (no_cable) {
			if ((ax772b_data->psc & 
			    (AX_SWRESET_IPPSL_0 | AX_SWRESET_IPPSL_1)) &&
			     !ax772b_data->pw_enabled) {
				/* 
				 * AX88772B already entered power saving state
				 */
				ax772b_data->pw_enabled = 1;
			}

		} else {
			/* AX88772B resumed from power saving state */
			if (ax772b_data->pw_enabled || 
				(jiffies > (ax772b_data->time_to_chk + 
				 AX88772B_WATCHDOG))) {
				if (ax772b_data->pw_enabled)
					ax772b_data->pw_enabled = 0;
				ax772b_data->Event = PHY_POWER_UP;
				ax772b_data->time_to_chk = jiffies;
			}
		}
	}

	if (ax772b_data->Event)
		queue_work (ax772b_data->ax_work, &ax772b_data->check_link);
}

static void
ax8817x_write_cmd_async(struct usbnet *dev, u8 cmd, u16 value, u16 index,
				    u16 size, void *data)
{
	struct usb_ctrlrequest *req;
	int status;
	struct urb *urb;

	if ((urb = usb_alloc_urb(0, GFP_ATOMIC)) == NULL) {
		netdev_dbg(dev->net, "Error allocating URB in write_cmd_async!");
		return;
	}

	if ((req = kmalloc(sizeof(struct usb_ctrlrequest), GFP_ATOMIC)) == NULL) {
		netdev_err(dev->net, "Failed to allocate memory for control request");
		usb_free_urb(urb);
		return;
	}

	req->bRequestType = USB_DIR_OUT | USB_TYPE_VENDOR | USB_RECIP_DEVICE;
	req->bRequest = cmd;
	req->wValue = cpu_to_le16(value);
	req->wIndex = cpu_to_le16(index);
	req->wLength = cpu_to_le16(size);

	usb_fill_control_urb(urb, dev->udev,
			     usb_sndctrlpipe(dev->udev, 0),
			     (void *)req, data, size,
			     ax8817x_async_cmd_callback, req);

	if((status = usb_submit_urb(urb, GFP_ATOMIC)) < 0) {
		netdev_err(dev->net, "Error submitting the control message: status=%d",
				status);
		kfree(req);
		usb_free_urb(urb);
	}
}

static void ax8817x_set_multicast(struct net_device *net)
{
	struct usbnet *dev = netdev_priv(net);
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	u8 rx_ctl = AX_RX_CTL_START | AX_RX_CTL_AB;

	if (net->flags & IFF_PROMISC) {
		rx_ctl |= AX_RX_CTL_PRO;
	} else if (net->flags & IFF_ALLMULTI
		   || netdev_mc_count(net) > AX_MAX_MCAST) {
		rx_ctl |= AX_RX_CTL_AMALL;
	} else if (netdev_mc_empty(net)) {
		/* just broadcast and directed */
	} else {
		/* We use the 20 byte dev->data
		 * for our 8 byte filter buffer
		 * to avoid allocating memory that
		 * is tricky to free later */
		struct netdev_hw_addr *ha;
		u32 crc_bits;

		memset(data->multi_filter, 0, AX_MCAST_FILTER_SIZE);

		/* Build the multicast hash filter. */
		netdev_for_each_mc_addr(ha, net) {
			crc_bits =
			    ether_crc(ETH_ALEN,
				      ha->addr) >> 26;
			data->multi_filter[crc_bits >> 3] |=
			    1 << (crc_bits & 7);
		}

		ax8817x_write_cmd_async(dev, AX_CMD_WRITE_MULTI_FILTER, 0, 0,
				   AX_MCAST_FILTER_SIZE, data->multi_filter);

		rx_ctl |= AX_RX_CTL_AM;
	}

	ax8817x_write_cmd_async(dev, AX_CMD_WRITE_RX_CTL, rx_ctl, 0, 0, NULL);
}

static void ax88772b_set_multicast(struct net_device *net)
{
	struct usbnet *dev = netdev_priv(net);
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	u16 rx_ctl = (AX_RX_CTL_START | AX_RX_CTL_AB | AX_RX_HEADER_DEFAULT);

	if (net->flags & IFF_PROMISC) {
		rx_ctl |= AX_RX_CTL_PRO;
	} else if (net->flags & IFF_ALLMULTI
		   || netdev_mc_count(net) > AX_MAX_MCAST) {
		rx_ctl |= AX_RX_CTL_AMALL;
	} else if (netdev_mc_empty(net)) {
		/* just broadcast and directed */
	} else {
		/* We use the 20 byte dev->data
		 * for our 8 byte filter buffer
		 * to avoid allocating memory that
		 * is tricky to free later */
		struct netdev_hw_addr *ha;
		u32 crc_bits;

		memset(data->multi_filter, 0, AX_MCAST_FILTER_SIZE);

		/* Build the multicast hash filter. */
		netdev_for_each_mc_addr(ha, net) {
			crc_bits =
			    ether_crc(ETH_ALEN,
				      ha->addr) >> 26;
			data->multi_filter[crc_bits >> 3] |=
			    1 << (crc_bits & 7);
		}

		ax8817x_write_cmd_async(dev, AX_CMD_WRITE_MULTI_FILTER, 0, 0,
				   AX_MCAST_FILTER_SIZE, data->multi_filter);

		rx_ctl |= AX_RX_CTL_AM;
	}

	ax8817x_write_cmd_async(dev, AX_CMD_WRITE_RX_CTL, rx_ctl, 0, 0, NULL);
}

static int ax8817x_mdio_read(struct net_device *netdev, int phy_id, int loc)
{
	struct usbnet *dev = netdev_priv(netdev);
	u16 res;
	u8 buf[1];

	ax8817x_write_cmd(dev, AX_CMD_SET_SW_MII, 0, 0, 0, &buf);
	ax8817x_read_cmd(dev, AX_CMD_READ_MII_REG, phy_id,
				(__u16)loc, 2, (u16 *)&res);
	ax8817x_write_cmd(dev, AX_CMD_SET_HW_MII, 0, 0, 0, &buf);

	return res & 0xffff;
}

/* same as above, but converts resulting value to cpu byte order */
static int ax8817x_mdio_read_le(struct net_device *netdev, int phy_id, int loc)
{
	return le16_to_cpu(ax8817x_mdio_read(netdev,phy_id, loc));
}

static void
ax8817x_mdio_write(struct net_device *netdev, int phy_id, int loc, int val)
{
	struct usbnet *dev = netdev_priv(netdev);
	u16 res = val;
	u8 buf[1];

	ax8817x_write_cmd(dev, AX_CMD_SET_SW_MII, 0, 0, 0, &buf);
	ax8817x_write_cmd(dev, AX_CMD_WRITE_MII_REG, phy_id,
				(__u16)loc, 2, (u16 *)&res);
	ax8817x_write_cmd(dev, AX_CMD_SET_HW_MII, 0, 0, 0, &buf);
}

static void
ax88772b_mdio_write(struct net_device *netdev, int phy_id, int loc, int val)
{
	struct usbnet *dev = netdev_priv(netdev);
	u16 res = val;
	u8 buf[1];

	ax8817x_write_cmd(dev, AX_CMD_SET_SW_MII, 0, 0, 0, &buf);
	ax8817x_write_cmd(dev, AX_CMD_WRITE_MII_REG, phy_id,
				(__u16)loc, 2, (u16 *)&res);

	if (loc == MII_ADVERTISE) {
		res = BMCR_ANENABLE | BMCR_ANRESTART;
		ax8817x_write_cmd(dev, AX_CMD_WRITE_MII_REG, phy_id,
				(__u16)MII_BMCR, 2, (u16 *)&res);
	}

	ax8817x_write_cmd(dev, AX_CMD_SET_HW_MII, 0, 0, 0, &buf);
}

/* same as above, but converts new value to le16 byte order before writing */
static void
ax8817x_mdio_write_le(struct net_device *netdev, int phy_id, int loc, int val)
{
	ax8817x_mdio_write( netdev, phy_id, loc, cpu_to_le16(val) );
}

static void
ax88772b_mdio_write_le(struct net_device *netdev, int phy_id, int loc, int val)
{
	ax88772b_mdio_write( netdev, phy_id, loc, cpu_to_le16(val) );
}

static int ax88772_suspend (struct usb_interface *intf, pm_message_t message)
{
	struct usbnet *dev = usb_get_intfdata(intf);
	u16 medium;

	ax8817x_read_cmd (dev, AX_CMD_READ_MEDIUM_MODE, 0, 0, 2, &medium);
	ax8817x_write_cmd (dev, AX_CMD_WRITE_MEDIUM_MODE,
			(medium & ~AX88772_MEDIUM_RX_ENABLE), 0, 0, NULL);

	return usbnet_suspend (intf, message);
}

static int ax88772b_suspend (struct usb_interface *intf, pm_message_t message)
{
	struct usbnet *dev = usb_get_intfdata(intf);
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	struct ax88772b_data *ax772b_data = data->priv.ax772b_data;
	u16 tmp16;
	u8 opt;

	ax8817x_read_cmd (dev, AX_CMD_READ_MEDIUM_MODE, 0, 0, 2, &tmp16);
	ax8817x_write_cmd (dev, AX_CMD_WRITE_MEDIUM_MODE,
			(tmp16 & ~AX88772_MEDIUM_RX_ENABLE), 0, 0, NULL);

	ax8817x_read_cmd(dev, AX_CMD_READ_MONITOR_MODE, 0, 0, 1, &opt);
	if (!(opt & AX_MONITOR_LINK) && !(opt & AX_MONITOR_MAGIC)) {
		ax8817x_write_cmd (dev, AX_CMD_SW_RESET,
			AX_SWRESET_IPRL | AX_SWRESET_IPPD, 0, 0, NULL);
	} else {

		if (ax772b_data->psc & AX_SWRESET_WOLLP) {
			tmp16 = ax8817x_mdio_read_le (dev->net,
					dev->mii.phy_id, MII_BMCR);
			ax8817x_mdio_write_le (dev->net, dev->mii.phy_id,
					MII_BMCR, tmp16 | BMCR_ANENABLE);

			ax8817x_write_cmd (dev, AX_CMD_SW_RESET,
				AX_SWRESET_IPRL | ax772b_data->psc, 0, 0, NULL);
		}

		if (ax772b_data->psc &
		    (AX_SWRESET_IPPSL_0 | AX_SWRESET_IPPSL_1)) {
			opt |= AX_MONITOR_LINK;
			ax8817x_write_cmd(dev, AX_CMD_WRITE_MONITOR_MODE,
					opt, 0, 0, NULL);
		}
	}

	return usbnet_suspend (intf, message);
}

static int ax88772_resume (struct usb_interface *intf)
{
	struct usbnet *dev = usb_get_intfdata(intf);

	netif_carrier_off (dev->net);

	return usbnet_resume (intf);
}

static int ax88772b_resume (struct usb_interface *intf)
{
	struct usbnet *dev = usb_get_intfdata(intf);
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	struct ax88772b_data *ax772b_data = data->priv.ax772b_data;

	if (ax772b_data->psc & AX_SWRESET_WOLLP) {
		ax8817x_write_cmd (dev, AX_CMD_SW_RESET,
				AX_SWRESET_IPRL | (ax772b_data->psc & 0x7FFF),
				0, 0, NULL);
	}

	if (ax772b_data->psc & (AX_SWRESET_IPPSL_0 | AX_SWRESET_IPPSL_1)) {
		ax88772a_phy_powerup (dev);
	}

	netif_carrier_off (dev->net);

	return usbnet_resume (intf);
}

static int ax88172_link_reset(struct usbnet *dev)
{
	u16 lpa;
	u16 adv;
	u16 res;
	u8 mode;

	mode = AX_MEDIUM_TX_ABORT_ALLOW | AX_MEDIUM_FLOW_CONTROL_EN;
	lpa = ax8817x_mdio_read_le(dev->net, dev->mii.phy_id, MII_LPA);
	adv = ax8817x_mdio_read_le(dev->net, dev->mii.phy_id, MII_ADVERTISE);
	res = mii_nway_result(lpa|adv);
	if (res & LPA_DUPLEX)
		mode |= AX_MEDIUM_FULL_DUPLEX;
	ax8817x_write_cmd(dev, AX_CMD_WRITE_MEDIUM_MODE, mode, 0, 0, NULL);

	return 0;
}

static void
ax8817x_get_wol(struct net_device *net, struct ethtool_wolinfo *wolinfo)
{
	struct usbnet *dev = netdev_priv(net);
	u8 opt;

	if (ax8817x_read_cmd(dev, AX_CMD_READ_MONITOR_MODE, 0, 0, 1, &opt) < 0) {
		wolinfo->supported = 0;
		wolinfo->wolopts = 0;
		return;
	}
	wolinfo->supported = WAKE_PHY | WAKE_MAGIC;
	wolinfo->wolopts = 0;

	if (opt & AX_MONITOR_LINK)
		wolinfo->wolopts |= WAKE_PHY;
	if (opt & AX_MONITOR_MAGIC)
		wolinfo->wolopts |= WAKE_MAGIC;
}

static int
ax8817x_set_wol(struct net_device *net, struct ethtool_wolinfo *wolinfo)
{
	struct usbnet *dev = netdev_priv(net);
	u8 opt = 0;

	if (wolinfo->wolopts & WAKE_PHY)
		opt |= AX_MONITOR_LINK;
	if (wolinfo->wolopts & WAKE_MAGIC)
		opt |= AX_MONITOR_MAGIC;

	if (ax8817x_write_cmd(dev, AX_CMD_WRITE_MONITOR_MODE,
			      opt, 0, 0, NULL) < 0)
		return -EINVAL;

	return 0;
}

static int ax8817x_get_eeprom_len(struct net_device *net)
{
	return AX_EEPROM_LEN;
}

static int ax8817x_get_eeprom(struct net_device *net,
			      struct ethtool_eeprom *eeprom, u8 *data)
{
	struct usbnet *dev = netdev_priv(net);
	u16 *ebuf = (u16 *)data;
	int i;

	/* Crude hack to ensure that we don't overwrite memory
	 * if an odd length is supplied
	 */
	if (eeprom->len % 2)
		return -EINVAL;

	eeprom->magic = AX_EEPROM_MAGIC;

	/* ax8817x returns 2 bytes from eeprom on read */
	for (i=0; i < eeprom->len / 2; i++) {
		if (ax8817x_read_cmd(dev, AX_CMD_READ_EEPROM,
			eeprom->offset + i, 0, 2, &ebuf[i]) < 0)
			return -EINVAL;
	}
	return 0;
}

static void ax8817x_get_drvinfo (struct net_device *net,
				 struct ethtool_drvinfo *info)
{
	/* Inherit standard device info */
	usbnet_get_drvinfo(net, info);
	info->eedump_len = 0x3e;
}

static int ax8817x_get_settings(struct net_device *net, struct ethtool_cmd *cmd)
{
	struct usbnet *dev = netdev_priv(net);

	return mii_ethtool_gset(&dev->mii,cmd);
}

static int ax8817x_set_settings(struct net_device *net, struct ethtool_cmd *cmd)
{
	struct usbnet *dev = netdev_priv(net);

	return mii_ethtool_sset(&dev->mii,cmd);
}

/* We need to override some ethtool_ops so we require our
   own structure so we don't interfere with other usbnet
   devices that may be connected at the same time. */
static struct ethtool_ops ax8817x_ethtool_ops = {
	.get_drvinfo		= ax8817x_get_drvinfo,
	.get_link		= ethtool_op_get_link,
	.get_msglevel		= usbnet_get_msglevel,
	.set_msglevel		= usbnet_set_msglevel,
	.get_wol		= ax8817x_get_wol,
	.set_wol		= ax8817x_set_wol,
	.get_eeprom_len	= ax8817x_get_eeprom_len,
	.get_eeprom		= ax8817x_get_eeprom,
	.get_settings		= ax8817x_get_settings,
	.set_settings		= ax8817x_set_settings,
};

static int ax8817x_ioctl (struct net_device *net, struct ifreq *rq, int cmd)
{
	struct usbnet *dev = netdev_priv(net);

	return generic_mii_ioctl(&dev->mii, if_mii(rq), cmd, NULL);
}

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,28)
static const struct net_device_ops ax88x72_netdev_ops = {
	.ndo_open		= usbnet_open,
	.ndo_stop		= usbnet_stop,
	.ndo_start_xmit		= usbnet_start_xmit,
	.ndo_tx_timeout		= usbnet_tx_timeout,
	.ndo_change_mtu		= usbnet_change_mtu,
	.ndo_set_mac_address 	= ax8817x_set_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_do_ioctl		= ax8817x_ioctl,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0)
	.ndo_set_rx_mode        = ax8817x_set_multicast,
#else
	.ndo_set_multicast_list = ax8817x_set_multicast,
#endif
};
#endif

static int ax8817x_bind(struct usbnet *dev, struct usb_interface *intf)
{
	int ret = 0;
	void *buf;
	int i;
	unsigned long gpio_bits = dev->driver_info->data;
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;

	usbnet_get_endpoints(dev,intf);

	buf = kmalloc(ETH_ALEN, GFP_KERNEL);
	if(!buf) {
		ret = -ENOMEM;
		goto out1;
	}

	/* Toggle the GPIOs in a manufacturer/model specific way */
	for (i = 2; i >= 0; i--) {
		if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_GPIOS,
					(gpio_bits >> (i * 8)) & 0xff, 0, 0,
					buf)) < 0)
			goto out2;
		msleep(5);
	}

	if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_RX_CTL,
				0x80, 0, 0, buf)) < 0) {
		dbg("send AX_CMD_WRITE_RX_CTL failed: %d", ret);
		goto out2;
	}

	/* Get the MAC address */
	memset(buf, 0, ETH_ALEN);
	if ((ret = ax8817x_read_cmd(dev, AX_CMD_READ_NODE_ID,
				0, 0, 6, buf)) < 0) {
		dbg("read AX_CMD_READ_NODE_ID failed: %d", ret);
		goto out2;
	}
	memcpy(dev->net->dev_addr, buf, ETH_ALEN);

	/* Get the PHY id */
	if ((ret = ax8817x_read_cmd(dev, AX_CMD_READ_PHY_ID,
				0, 0, 2, buf)) < 0) {
		dbg("error on read AX_CMD_READ_PHY_ID: %02x", ret);
		goto out2;
	} else if (ret < 2) {
		/* this should always return 2 bytes */
		dbg("AX_CMD_READ_PHY_ID returned less than 2 bytes: ret=%02x",
				ret);
		ret = -EIO;
		goto out2;
	}

	/* Initialize MII structure */
	dev->mii.dev = dev->net;
	dev->mii.mdio_read = ax8817x_mdio_read_le;
	dev->mii.mdio_write = ax8817x_mdio_write_le;
	dev->mii.phy_id_mask = 0x3f;
	dev->mii.reg_num_mask = 0x1f;
	dev->mii.phy_id = *((u8 *)buf + 1);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
	dev->net->do_ioctl = ax8817x_ioctl;
	dev->net->set_multicast_list = ax8817x_set_multicast;
	dev->net->set_mac_address = ax8817x_set_mac_addr;
#else
	dev->net->netdev_ops = &ax88x72_netdev_ops;
#endif

	dev->net->ethtool_ops = &ax8817x_ethtool_ops;

	/* Register suspend and resume functions */
	data->suspend = usbnet_suspend;
	data->resume = usbnet_resume;

	ax8817x_mdio_write_le(dev->net, dev->mii.phy_id, MII_BMCR, BMCR_RESET);
	ax8817x_mdio_write_le(dev->net, dev->mii.phy_id, MII_ADVERTISE,
		ADVERTISE_ALL | ADVERTISE_CSMA | ADVERTISE_PAUSE_CAP);
	mii_nway_restart(&dev->mii);

	printk (version);

	return 0;
out2:
	kfree(buf);
out1:
	return ret;
}

static struct ethtool_ops ax88772_ethtool_ops = {
	.get_drvinfo		= ax8817x_get_drvinfo,
	.get_link		= ethtool_op_get_link,
	.get_msglevel		= usbnet_get_msglevel,
	.set_msglevel		= usbnet_set_msglevel,
	.get_wol		= ax8817x_get_wol,
	.set_wol		= ax8817x_set_wol,
	.get_eeprom_len		= ax8817x_get_eeprom_len,
	.get_eeprom		= ax8817x_get_eeprom,
	.get_settings		= ax8817x_get_settings,
	.set_settings		= ax8817x_set_settings,
};

static int ax88772_bind(struct usbnet *dev, struct usb_interface *intf)
{
	int ret;
	void *buf;
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	struct ax88772_data *ax772_data = NULL;

	usbnet_get_endpoints(dev,intf);

	buf = kmalloc(6, GFP_KERNEL);
	if(!buf) {
		dbg ("Cannot allocate memory for buffer");
		ret = -ENOMEM;
		goto out1;
	}

        ax772_data = kmalloc (sizeof(*ax772_data), GFP_KERNEL);
        if (!ax772_data) {
                dbg ("Cannot allocate memory for AX88772 data");
                kfree (buf);
                return -ENOMEM;
        }
        memset (ax772_data, 0, sizeof(*ax772_data));
        data->priv.ax772_data = ax772_data;

        ax772_data->ax_work = create_singlethread_workqueue ("ax88772");
        if (!ax772_data->ax_work) {
                kfree (ax772_data);
                kfree (buf);
                return -ENOMEM;
        }

        ax772_data->dev = dev;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
        INIT_WORK (&ax772_data->check_link, ax88772_link_reset, dev);
#else
        INIT_WORK (&ax772_data->check_link, ax88772_link_reset);
#endif

	/* reload eeprom data */
	if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_GPIOS,
				     0x00B0, 0, 0, buf)) < 0)
		goto out2;

	msleep(5);

	/* Initialize MII structure */
	dev->mii.dev = dev->net;
	dev->mii.mdio_read = ax8817x_mdio_read_le;
	dev->mii.mdio_write = ax8817x_mdio_write_le;
	dev->mii.phy_id_mask = 0xff;
	dev->mii.reg_num_mask = 0xff;

	/* Get the PHY id */
	if ((ret = ax8817x_read_cmd(dev, AX_CMD_READ_PHY_ID,
			0, 0, 2, buf)) < 0) {
		dbg("Error reading PHY ID: %02x", ret);
		goto out2;
	} else if (ret < 2) {
		/* this should always return 2 bytes */
		dbg("AX_CMD_READ_PHY_ID returned less than 2 bytes: ret=%02x",
		    ret);
		ret = -EIO;
		goto out2;
	}
	dev->mii.phy_id = *((u8 *)buf + 1);

	if (dev->mii.phy_id == 0x10)
	{
		if ((ret = ax8817x_write_cmd(dev, AX_CMD_SW_PHY_SELECT,
					0x0001, 0, 0, buf)) < 0) {
			dbg("Select PHY #1 failed: %d", ret);
			goto out2;
		}

		if ((ret = ax8817x_write_cmd(dev, AX_CMD_SW_RESET, AX_SWRESET_IPPD,
					0, 0, buf)) < 0) {
			dbg("Failed to power down internal PHY: %d", ret);
			goto out2;
		}

		msleep(150);
		if ((ret = ax8817x_write_cmd(dev, AX_CMD_SW_RESET, AX_SWRESET_CLEAR,
					0, 0, buf)) < 0) {
			dbg("Failed to perform software reset: %d", ret);
			goto out2;
		}

		msleep(150);
		if ((ret = ax8817x_write_cmd(dev, AX_CMD_SW_RESET,
		     			AX_SWRESET_IPRL | AX_SWRESET_PRL,
					0, 0, buf)) < 0) {
			dbg("Failed to set Internal/External PHY reset control: %d",
						ret);
			goto out2;
		}
	}
	else
	{
		if ((ret = ax8817x_write_cmd(dev, AX_CMD_SW_PHY_SELECT,
					0x0000, 0, 0, buf)) < 0) {
			dbg("Select PHY #1 failed: %d", ret);
			goto out2;
		}

		if ((ret = ax8817x_write_cmd(dev, AX_CMD_SW_RESET,
					AX_SWRESET_IPPD | AX_SWRESET_PRL, 0, 0, buf)) < 0) {
			dbg("Failed to power down internal PHY: %d", ret);
			goto out2;
		}
	}

	msleep(150);
	if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_RX_CTL,
				0x0000, 0, 0, buf)) < 0) {
		dbg("Failed to reset RX_CTL: %d", ret);
		goto out2;
	}

	/* Get the MAC address */
	memset(buf, 0, ETH_ALEN);
	if ((ret = ax8817x_read_cmd(dev, AX88772_CMD_READ_NODE_ID,
				0, 0, ETH_ALEN, buf)) < 0) {
		dbg("Failed to read MAC address: %d", ret);
		goto out2;
	}
	memcpy(dev->net->dev_addr, buf, ETH_ALEN);

	if ((ret = ax8817x_write_cmd(dev, AX_CMD_SET_SW_MII,
				0, 0, 0, buf)) < 0) {
		dbg("Enabling software MII failed: %d", ret);
		goto out2;
	}

	if (dev->mii.phy_id == 0x10)
	{
		if ((ret = ax8817x_mdio_read_le(dev->net, dev->mii.phy_id, 2)) != 0x003b)
		{
			dbg("Read PHY register 2 must be 0x3b00: %d", ret);
			goto out2;
		}
		
		if ((ret = ax8817x_write_cmd(dev, AX_CMD_SW_RESET, AX_SWRESET_PRL,
					0, 0, buf)) < 0) {
			dbg("Set external PHY reset pin level: %d", ret);
			goto out2;
		}
		msleep(150);
		if ((ret = ax8817x_write_cmd(dev, AX_CMD_SW_RESET,
			 			AX_SWRESET_IPRL | AX_SWRESET_PRL,
					0, 0, buf)) < 0) {
			dbg("Set Internal/External PHY reset control: %d", ret);
			goto out2;
		}
		msleep(150);
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
	dev->net->do_ioctl = ax8817x_ioctl;
	dev->net->set_multicast_list = ax8817x_set_multicast;
	dev->net->set_mac_address = ax8817x_set_mac_addr;
#else
	dev->net->netdev_ops = &ax88x72_netdev_ops;
#endif

	dev->net->ethtool_ops = &ax88772_ethtool_ops;

	/* Register suspend and resume functions */
	data->suspend = ax88772_suspend;
	data->resume = ax88772_resume;

	ax8817x_mdio_write_le(dev->net, dev->mii.phy_id, MII_BMCR, BMCR_RESET);
	ax8817x_mdio_write_le(dev->net, dev->mii.phy_id, MII_ADVERTISE,
			ADVERTISE_ALL | ADVERTISE_CSMA);

	mii_nway_restart(&dev->mii);
        ax772_data->autoneg_start = jiffies;
        ax772_data->Event = WAIT_AUTONEG_COMPLETE;

	if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_MEDIUM_MODE,
				AX88772_MEDIUM_DEFAULT, 0, 0, buf)) < 0) {
		dbg("Write medium mode register: %d", ret);
		goto out2;
	}

	if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_IPG0,
				AX88772_IPG0_DEFAULT | AX88772_IPG1_DEFAULT << 8,
				AX88772_IPG2_DEFAULT, 0, buf)) < 0) {
		dbg("Write IPG,IPG1,IPG2 failed: %d", ret);
		goto out2;
	}
	if ((ret =
	     ax8817x_write_cmd(dev, AX_CMD_SET_HW_MII, 0, 0, 0, &buf)) < 0) {
		dbg("Failed to set hardware MII: %02x", ret);
		goto out2;
	}

	/* Set RX_CTL to default values with 2k buffer, and enable cactus */
	if ((ret =
	     ax8817x_write_cmd(dev, AX_CMD_WRITE_RX_CTL, 0x0088, 0, 0,
			       buf)) < 0) {
		dbg("Reset RX_CTL failed: %d", ret);
		goto out2;
	}

	/* Asix framing packs multiple eth frames into a 2K usb bulk transfer */
	if (dev->driver_info->flags & FLAG_FRAMING_AX) {
		/* hard_mtu  is still the default - the device does not support
		   jumbo eth frames */
		dev->rx_urb_size = 2048;
	}

	kfree (buf);
	printk (version);
	return 0;

out2:
	destroy_workqueue (ax772_data->ax_work);
        kfree (ax772_data);
	kfree(buf);
out1:
	return ret;
}

static void ax88772_unbind(struct usbnet *dev, struct usb_interface *intf)
{
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	struct ax88772_data *ax772_data = data->priv.ax772_data;

	if (ax772_data) {

		flush_workqueue (ax772_data->ax_work);
		destroy_workqueue (ax772_data->ax_work);

		/* stop MAC operation */
		ax8817x_write_cmd(dev, AX_CMD_WRITE_RX_CTL,
					AX_RX_CTL_STOP, 0, 0, NULL);

		/* Power down PHY */
		ax8817x_write_cmd(dev, AX_CMD_SW_RESET,
					AX_SWRESET_IPPD, 0, 0, NULL);

		kfree (ax772_data);
	}
}

static int ax88772a_phy_powerup (struct usbnet *dev)
{
	int ret;
	/* set the embedded Ethernet PHY in power-down state */
	if ((ret = ax8817x_write_cmd(dev, AX_CMD_SW_RESET,
			AX_SWRESET_IPPD | AX_SWRESET_IPRL, 0, 0, NULL)) < 0) {
		dbg("Failed to power down PHY: %d", ret);
		return ret;
	}

	msleep(10);

	
	/* set the embedded Ethernet PHY in power-up state */
	if ((ret = ax8817x_write_cmd(dev, AX_CMD_SW_RESET,
			AX_SWRESET_IPRL, 0, 0, NULL)) < 0) {
		dbg("Failed to reset PHY: %d", ret);
		return ret;
	}

	msleep(600);

	/* set the embedded Ethernet PHY in reset state */
	if ((ret = ax8817x_write_cmd(dev, AX_CMD_SW_RESET,
			AX_SWRESET_CLEAR, 0, 0, NULL)) < 0) {
		dbg("Failed to power up PHY: %d", ret);
		return ret;
	}

	/* set the embedded Ethernet PHY in power-up state */
	if ((ret = ax8817x_write_cmd(dev, AX_CMD_SW_RESET,
			AX_SWRESET_IPRL, 0, 0, NULL)) < 0) {
		dbg("Failed to reset PHY: %d", ret);
		return ret;
	}

	return 0;
}

static int ax88772a_bind(struct usbnet *dev, struct usb_interface *intf)
{
	int ret = -EIO;
	void *buf;
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	struct ax88772a_data *ax772a_data = NULL;
	u16 EepromData;

	usbnet_get_endpoints(dev,intf);

	buf = kmalloc(6, GFP_KERNEL);
	if(!buf) {
		dbg ("Cannot allocate memory for buffer");
		ret = -ENOMEM;
		goto out1;
	}

	ax772a_data = kmalloc (sizeof(*ax772a_data), GFP_KERNEL);
	if (!ax772a_data) {
		dbg ("Cannot allocate memory for AX88772A data");
		kfree (buf);
		return -ENOMEM;
	}
	memset (ax772a_data, 0, sizeof(*ax772a_data));
	data->priv.ax772a_data = ax772a_data;

	ax772a_data->ax_work = create_singlethread_workqueue ("ax88772a");
	if (!ax772a_data->ax_work) {
		kfree (ax772a_data);
		kfree (buf);
		return -ENOMEM;
	}

	ax772a_data->dev = dev;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
	INIT_WORK (&ax772a_data->check_link, ax88772a_link_reset, dev);
#else
	INIT_WORK (&ax772a_data->check_link, ax88772a_link_reset);
#endif

	/* Get the EEPROM data*/
	if ((ret = ax8817x_read_cmd(dev, AX_CMD_READ_EEPROM, 
			0x0017, 0, 2, (void *)(&EepromData))) < 0) {
		dbg("read SROM address 17h failed: %d", ret);
		goto out2;
	}
	ax772a_data->EepromData = le16_to_cpu(EepromData);
	/* End of get EEPROM data */

	/* reload eeprom data */
	if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_GPIOS,
			AXGPIOS_RSE, 0, 0, buf)) < 0)
		goto out2;

	msleep(5);

	/* Initialize MII structure */
	dev->mii.dev = dev->net;
	dev->mii.mdio_read = ax8817x_mdio_read_le;
	dev->mii.mdio_write = ax8817x_mdio_write_le;
	dev->mii.phy_id_mask = 0xff;
	dev->mii.reg_num_mask = 0xff;

	/* Get the PHY id */
	if ((ret = ax8817x_read_cmd(dev, AX_CMD_READ_PHY_ID,
			0, 0, 2, buf)) < 0) {
		dbg("Error reading PHY ID: %02x", ret);
		goto out2;
	} else if (ret < 2) {
		/* this should always return 2 bytes */
		dbg("AX_CMD_READ_PHY_ID returned less than 2 bytes: ret=%02x",
		    ret);
		goto out2;
	}
	dev->mii.phy_id = *((u8 *)buf + 1);

	if(dev->mii.phy_id != 0x10) {
		dbg("Got wrong PHY ID: %02x", dev->mii.phy_id);
		goto out2;
	}

	/* select the embedded 10/100 Ethernet PHY */
	if ((ret = ax8817x_write_cmd(dev, AX_CMD_SW_PHY_SELECT,
			AX_PHYSEL_SSEN | AX_PHYSEL_PSEL | AX_PHYSEL_SSMII,
			0, 0, buf)) < 0) {
		dbg("Select PHY #1 failed: %d", ret);
		goto out2;
	}

	if ((ret = ax88772a_phy_powerup (dev)) < 0)
		goto out2;

	/* stop MAC operation */
	if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_RX_CTL,
			AX_RX_CTL_STOP, 0, 0, buf)) < 0) {
		dbg("Reset RX_CTL failed: %d", ret);
		goto out2;
	}

	/* Get the MAC address */
	memset(buf, 0, ETH_ALEN);
	if ((ret = ax8817x_read_cmd(dev, AX88772_CMD_READ_NODE_ID,
				0, 0, ETH_ALEN, buf)) < 0) {
		dbg("Failed to read MAC address: %d", ret);
		goto out2;
	}
	memcpy(dev->net->dev_addr, buf, ETH_ALEN);

	/* make sure the driver can enable sw mii operation */
	if ((ret = ax8817x_write_cmd(dev, AX_CMD_SET_SW_MII,
			0, 0, 0, buf)) < 0) {
		dbg("Enabling software MII failed: %d", ret);
		goto out2;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
	dev->net->do_ioctl = ax8817x_ioctl;
	dev->net->set_multicast_list = ax8817x_set_multicast;
	dev->net->set_mac_address = ax8817x_set_mac_addr;
#else
	dev->net->netdev_ops = &ax88x72_netdev_ops;
#endif

	dev->net->ethtool_ops = &ax88772_ethtool_ops;

	/* Register suspend and resume functions */
	data->suspend = ax88772_suspend;
	data->resume = ax88772_resume;

	ax8817x_mdio_write_le(dev->net, dev->mii.phy_id, MII_BMCR, BMCR_RESET);
	ax8817x_mdio_write_le(dev->net, dev->mii.phy_id, MII_ADVERTISE,
			ADVERTISE_ALL | ADVERTISE_CSMA | ADVERTISE_PAUSE_CAP);

	mii_nway_restart(&dev->mii);
	ax772a_data->autoneg_start = jiffies;
	ax772a_data->Event = WAIT_AUTONEG_COMPLETE;

	if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_MEDIUM_MODE,
				AX88772_MEDIUM_DEFAULT, 0, 0, buf)) < 0) {
		dbg("Write medium mode register: %d", ret);
		goto out2;
	}

	if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_IPG0,
				AX88772A_IPG0_DEFAULT | AX88772A_IPG1_DEFAULT << 8,
				AX88772A_IPG2_DEFAULT, 0, buf)) < 0) {
		dbg("Write IPG,IPG1,IPG2 failed: %d", ret);
		goto out2;
	}

	/* Set RX_CTL to default values with 2k buffer, and enable cactus */
	if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_RX_CTL,
			(AX_RX_CTL_START | AX_RX_CTL_AB),
			0, 0, buf)) < 0) {
		dbg("Reset RX_CTL failed: %d", ret);
		goto out2;
	}

	/* Asix framing packs multiple eth frames into a 2K usb bulk transfer */
	if (dev->driver_info->flags & FLAG_FRAMING_AX) {
		/* hard_mtu  is still the default - the device does not support
		   jumbo eth frames */
		dev->rx_urb_size = 2048;
	}

	kfree (buf);

	printk (version);
	return ret;
out2:
	destroy_workqueue (ax772a_data->ax_work);
	kfree (ax772a_data);
	kfree (buf);
out1:
	return ret;
}

static void ax88772a_unbind(struct usbnet *dev, struct usb_interface *intf)
{
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	struct ax88772a_data *ax772a_data = data->priv.ax772a_data;

	if (ax772a_data) {

		flush_workqueue (ax772a_data->ax_work);
		destroy_workqueue (ax772a_data->ax_work);

		/* stop MAC operation */
		ax8817x_write_cmd(dev, AX_CMD_WRITE_RX_CTL,
					AX_RX_CTL_STOP, 0, 0, NULL);

		/* Power down PHY */
		ax8817x_write_cmd(dev, AX_CMD_SW_RESET,
					AX_SWRESET_IPPD, 0, 0, NULL);

		kfree (ax772a_data);
	}
}

static int ax88772b_set_csums(struct usbnet *dev)
{
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	struct ax88772b_data *ax772b_data = data->priv.ax772b_data;
	int ret;
	u16 checksum, checksum1;// = AX_RXCOE_PPPOE;

	if (ax772b_data->checksum & AX_RX_CHECKSUM) {
		#if defined(AX_PARTIAL_CSUM)
		checksum = AX_RXCOE_FOPC;
		checksum1 = AX_RXCOE_RPCE;
		printk ("Enable RX partial checksum offload\n");
		#else
		checksum = (AX_RXCOE_IPCE | AX_RXCOE_IPVE | AX_RXCOE_V6VE
			    | AX_RXCOE_TCPE | AX_RXCOE_UDPE | AX_RXCOE_ICV6
			    | AX_RXCOE_TCPV6 | AX_RXCOE_UDPV6	);
		checksum1 = AX_RXCOE_PPPOE;
		printk ("Enable RX full checksum offload\n");
		#endif
	} else {
		checksum = 0;
		printk ("Disable RX checksum offload\n");
	}

	ret = ax8817x_write_cmd (dev, AX_CMD_WRITE_RXCOE_CTL,
				 checksum, checksum1, 0, NULL);
	if (ret)
		goto error_out;

	if (ax772b_data->checksum & AX_TX_CHECKSUM) {
		checksum = (AX_TXCOE_TCP | AX_TXCOE_UDP | AX_TXCOE_TCPV6 | AX_TXCOE_UDPV6);
		checksum1 = AX_TXCOE_PPPE;
		printk ("Enable TX checksum offload\n");
	} else {
		checksum = 0;
		printk ("Disable RX checksum offload\n");
	}

	ret = ax8817x_write_cmd (dev, AX_CMD_WRITE_TXCOE_CTL,
				 checksum, checksum1, 0, NULL);
error_out:
	return ret;
}

static u32 ax88772b_get_rx_csum(struct net_device *netdev)
{
	struct usbnet *dev = netdev_priv(netdev);
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	struct ax88772b_data *ax772b_data = data->priv.ax772b_data;

	return (ax772b_data->checksum & AX_RX_CHECKSUM);
}

static int ax88772b_set_rx_csum(struct net_device *netdev, u32 val)
{
	struct usbnet *dev = netdev_priv(netdev);
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	struct ax88772b_data *ax772b_data = data->priv.ax772b_data;

	if (val)
		ax772b_data->checksum |= AX_RX_CHECKSUM;
	else
		ax772b_data->checksum &= ~AX_RX_CHECKSUM;

	return ax88772b_set_csums(dev);
}

static int ax88772b_set_tx_csum(struct net_device *netdev, u32 val)
{
	struct usbnet *dev = netdev_priv(netdev);
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	struct ax88772b_data *ax772b_data = data->priv.ax772b_data;

	if (val)
		ax772b_data->checksum |= AX_TX_CHECKSUM;
	else
		ax772b_data->checksum &= ~AX_TX_CHECKSUM;

	ethtool_op_set_tx_hw_csum(netdev, val);

	return ax88772b_set_csums(dev);
}

static struct ethtool_ops ax88772b_ethtool_ops = {
	.get_drvinfo		= ax8817x_get_drvinfo,
	.get_link		= ethtool_op_get_link,
	.get_msglevel		= usbnet_get_msglevel,
	.set_msglevel		= usbnet_set_msglevel,
	.get_wol		= ax8817x_get_wol,
	.set_wol		= ax8817x_set_wol,
	.get_eeprom_len		= ax8817x_get_eeprom_len,
	.get_eeprom		= ax8817x_get_eeprom,
	.get_settings		= ax8817x_get_settings,
	.set_settings		= ax8817x_set_settings,
	.set_tx_csum		= ax88772b_set_tx_csum,
	.get_rx_csum		= ax88772b_get_rx_csum,
	.set_rx_csum		= ax88772b_set_rx_csum,
};

#if LINUX_VERSION_CODE > KERNEL_VERSION(2,6,28)
static const struct net_device_ops ax88772b_netdev_ops = {
	.ndo_open		= usbnet_open,
	.ndo_stop		= usbnet_stop,
	.ndo_start_xmit		= usbnet_start_xmit,
	.ndo_tx_timeout		= usbnet_tx_timeout,
	.ndo_change_mtu		= usbnet_change_mtu,
	.ndo_set_mac_address 	= ax8817x_set_mac_addr,
	.ndo_validate_addr	= eth_validate_addr,
	.ndo_do_ioctl		= ax8817x_ioctl,
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,2,0)
	.ndo_set_rx_mode        = ax88772b_set_multicast,
#else
	.ndo_set_multicast_list = ax88772b_set_multicast,
#endif
};
#endif

static int ax88772b_bind(struct usbnet *dev, struct usb_interface *intf)
{
	int ret;
	u8 buf[6];
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	struct ax88772b_data *ax772b_data;
	u16 tmp16;
	u8 i;

	usbnet_get_endpoints(dev,intf);

	ax772b_data = kmalloc (sizeof(*ax772b_data), GFP_KERNEL);
	if (!ax772b_data) {
		dbg ("Cannot allocate memory for AX88772B data");
		return -ENOMEM;
	}
	memset (ax772b_data, 0, sizeof(*ax772b_data));
	data->priv.ax772b_data = ax772b_data;

	ax772b_data->ax_work = create_singlethread_workqueue ("ax88772b");
	if (!ax772b_data->ax_work) {
		kfree (ax772b_data);
		return -ENOMEM;
	}

	ax772b_data->dev = dev;
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
	INIT_WORK (&ax772b_data->check_link, ax88772b_link_reset, dev);
#else
	INIT_WORK (&ax772b_data->check_link, ax88772b_link_reset);
#endif

	/* reload eeprom data */
	if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_GPIOS,
			AXGPIOS_RSE, 0, 0, buf)) < 0) {
		dbg("Failed to enable GPIO finction: %d", ret);
		goto err_out;
	}
	msleep(5);

	/* Get the EEPROM data*/
	if ((ret = ax8817x_read_cmd (dev, AX_CMD_READ_EEPROM,
				     0x18, 0, 2, (void *)(&tmp16))) < 0) {
		dbg("read SROM address 18h failed: %d", ret);
		goto err_out;
	}

	/* Get the MAC address */
	memset(buf, 0, ETH_ALEN);
	for (i = 0; i < (ETH_ALEN >> 1); i++) {
		if ((ret = ax8817x_read_cmd (dev, AX_CMD_READ_EEPROM,
					0x04 + i, 0, 2, (buf + i * 2))) < 0) {
			dbg("read SROM address 04h failed: %d", ret);
			goto err_out;
		}
	}
	memcpy(dev->net->dev_addr, buf, ETH_ALEN);

	ax772b_data->psc = le16_to_cpu(tmp16) & 0xFF00;
	/* End of get EEPROM data */

	/* Set the MAC address */
	if ((ret = ax8817x_write_cmd (dev, AX88772_CMD_WRITE_NODE_ID,
			0, 0, ETH_ALEN, dev->net->dev_addr)) < 0) {
		dbg("set MAC address failed: %d", ret);
		goto err_out;
	}

	/* Initialize MII structure */
	dev->mii.dev = dev->net;
	dev->mii.mdio_read = ax8817x_mdio_read_le;
	dev->mii.mdio_write = ax88772b_mdio_write_le;
	dev->mii.phy_id_mask = 0xff;
	dev->mii.reg_num_mask = 0xff;

	/* Get the PHY id */
	if ((ret = ax8817x_read_cmd(dev, AX_CMD_READ_PHY_ID,
			0, 0, 2, buf)) < 0) {
		dbg("Error reading PHY ID: %02x", ret);
		goto err_out;
	} else if (ret < 2) {
		/* this should always return 2 bytes */
		dbg("AX_CMD_READ_PHY_ID returned less than 2 bytes: ret=%02x",
		    ret);
		ret = -EIO;
		goto err_out;
	}
	dev->mii.phy_id = *((u8 *)buf + 1);

	if(dev->mii.phy_id != 0x10) {
		dbg("Got wrong PHY ID: %02x", dev->mii.phy_id);
		ret = -EIO;
		goto err_out;
	}

	/* select the embedded 10/100 Ethernet PHY */
	if ((ret = ax8817x_write_cmd(dev, AX_CMD_SW_PHY_SELECT,
			AX_PHYSEL_SSEN | AX_PHYSEL_PSEL | AX_PHYSEL_SSMII,
			0, 0, buf)) < 0) {
		dbg("Select PHY #1 failed: %d", ret);
		goto err_out;
	}

	if ((ret = ax88772a_phy_powerup (dev)) < 0)
		goto err_out;

	/* stop MAC operation */
	if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_RX_CTL,
			AX_RX_CTL_STOP, 0, 0, buf)) < 0) {
		dbg("Reset RX_CTL failed: %d", ret);
		goto err_out;
	}

	/* make sure the driver can enable sw mii operation */
	if ((ret = ax8817x_write_cmd(dev, AX_CMD_SET_SW_MII,
			0, 0, 0, buf)) < 0) {
		dbg("Enabling software MII failed: %d", ret);
		goto err_out;
	}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
	dev->net->do_ioctl = ax8817x_ioctl;
	dev->net->set_multicast_list = ax88772b_set_multicast;
	dev->net->set_mac_address = ax8817x_set_mac_addr;
#else
	dev->net->netdev_ops = &ax88772b_netdev_ops;
#endif

	dev->net->ethtool_ops = &ax88772b_ethtool_ops;

	/* Register suspend and resume functions */
	data->suspend = ax88772b_suspend;
	data->resume = ax88772b_resume;

	tmp16 = ax8817x_mdio_read_le(dev->net, dev->mii.phy_id, 0x12);
	ax8817x_mdio_write_le(dev->net, dev->mii.phy_id, 0x12,
			((tmp16 & 0xFF9F) | 0x0040));

	ax8817x_mdio_write_le(dev->net, dev->mii.phy_id, MII_ADVERTISE,
			ADVERTISE_ALL | ADVERTISE_CSMA | ADVERTISE_PAUSE_CAP);

	mii_nway_restart(&dev->mii);

	if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_MEDIUM_MODE,
				AX88772_MEDIUM_DEFAULT, 0, 0, buf)) < 0) {
		dbg("Failed to write medium mode: %d", ret);
		goto err_out;
	}

	if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_IPG0,
			AX88772A_IPG0_DEFAULT | AX88772A_IPG1_DEFAULT << 8,
			AX88772A_IPG2_DEFAULT, 0, buf)) < 0) {
		dbg("Failed to write interframe gap: %d", ret);
		goto err_out;
	}

	dev->net->features |= NETIF_F_HW_CSUM;
	ax772b_data->checksum = AX_RX_CHECKSUM | AX_TX_CHECKSUM;
	if ((ret = ax88772b_set_csums(dev)) < 0) {
		dbg("Write RX_COE/TX_COE failed: %d", ret);
		goto err_out;
	}

	if (dev->udev->speed == USB_SPEED_HIGH) {
		if ((ret = ax8817x_write_cmd (dev, 0x2A,
				0x8004, 0x851E, 0, buf)) < 0) {
			dbg("Reset RX_CTL failed: %d", ret);
			goto err_out;
		}

		dev->rx_urb_size = AX88772B_DEF_BURST_LEN;

	} else {
		if ((ret = ax8817x_write_cmd (dev, 0x2A,
				0x8000, 0x8000, 0, buf)) < 0) {
			dbg("Reset RX_CTL failed: %d", ret);
			goto err_out;
		}
		dev->rx_urb_size = 2048;
	}

	/* 
	 * Set RX_CTL to default values with Rx header mode 1 and
	 * ip header aligned double word
	 */
	if ((ret = ax8817x_write_cmd (dev, AX_CMD_WRITE_RX_CTL,
			(AX_RX_CTL_START | AX_RX_CTL_AB | AX_RX_HEADER_DEFAULT),
			0, 0, buf)) < 0) {
		dbg("Reset RX_CTL failed: %d", ret);
		goto err_out;
	}

	/* Overwrite power saving configuration from eeprom */
	if ((ret = ax8817x_write_cmd (dev, AX_CMD_SW_RESET,
	    AX_SWRESET_IPRL | (ax772b_data->psc & 0x7FFF), 0, 0, buf)) < 0) {
		dbg("Failed to configure PHY power saving: %d", ret);
		goto err_out;
	}

	printk (version);
	return ret;
err_out:
	kfree (ax772b_data);
	return ret;
}

static void ax88772b_unbind(struct usbnet *dev, struct usb_interface *intf)
{
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	struct ax88772b_data *ax772b_data = data->priv.ax772b_data;

	if (ax772b_data) {

		flush_workqueue (ax772b_data->ax_work);
		destroy_workqueue (ax772b_data->ax_work);

		/* stop MAC operation */
		ax8817x_write_cmd(dev, AX_CMD_WRITE_RX_CTL,
					AX_RX_CTL_STOP, 0, 0, NULL);

		/* Power down PHY */
		ax8817x_write_cmd(dev, AX_CMD_SW_RESET,
					AX_SWRESET_IPPD, 0, 0, NULL);

		kfree (ax772b_data);
	}
}

static int ax88178_media_check (struct usbnet *dev, struct ax88178_data *ax178dataptr)
{
	int ret,fullduplex;
	u16 phylinkstatus1, phylinkstatus2, data16, tempshort = 0;
	u16 media;

	if ((ret =ax8817x_read_cmd(dev,AX_CMD_READ_MII_REG,dev->mii.phy_id,
		GMII_PHY_ANLPAR, REG_LENGTH, &data16)) < 0) {
		dbg("error on reading MII register 5 failed: %02x", ret);
		return ret;   //
	}
	phylinkstatus1 = le16_to_cpu(data16);

	if ((ret = ax8817x_read_cmd (dev, AX_CMD_READ_MII_REG,
			dev->mii.phy_id, GMII_PHY_1000BT_STATUS,
			REG_LENGTH, &data16)) < 0) {
		dbg("error on reading MII register 0x0a failed: %02x", ret);
		return ret;   //
	}
	phylinkstatus2 = le16_to_cpu(data16);

	if(ax178dataptr->PhyMode == PHY_MODE_MARVELL){ //1st generation Marvel PHY
		if(ax178dataptr->LedMode == 1){
			if ((ret = ax8817x_read_cmd (dev, AX_CMD_READ_MII_REG,
					dev->mii.phy_id, MARVELL_MANUAL_LED,
					REG_LENGTH, &data16)) < 0) {
				dbg("error on reading MII register"
					" 0x19 failed: %02x", ret);
				return ret;   //
			}
			tempshort = le16_to_cpu(data16);
			tempshort &=0xfc0f;
		}
	}

	fullduplex=1;
	if(phylinkstatus2 & 
	   (GMII_1000_AUX_STATUS_FD_CAPABLE | GMII_1000_AUX_STATUS_HD_CAPABLE)){
	/* 1000BT full duplex */
		media = MEDIUM_GIGA_MODE | MEDIUM_FULL_DUPLEX_MODE |
			MEDIUM_ENABLE_125MHZ | MEDIUM_ENABLE_RECEIVE;
		if(ax178dataptr->PhyMode == PHY_MODE_MARVELL){
			if(ax178dataptr->LedMode == 1){
				tempshort|= 0x3e0;
			}
		}
	} else if(phylinkstatus1 & GMII_ANLPAR_100TXFD) {
	/* 100BT full duplex */
		media = MEDIUM_FULL_DUPLEX_MODE | MEDIUM_ENABLE_RECEIVE |
			MEDIUM_MII_100M_MODE;
		if(ax178dataptr->PhyMode == PHY_MODE_MARVELL){
			if(ax178dataptr->LedMode == 1){
				tempshort|= 0x3b0;
			}
		}
	}else if(phylinkstatus1 & GMII_ANLPAR_100TX) {
	/* 100BT half duplex */
		media = MEDIUM_ENABLE_RECEIVE | MEDIUM_MII_100M_MODE;
		fullduplex=0;
		if(ax178dataptr->PhyMode == PHY_MODE_MARVELL) {
			if(ax178dataptr->LedMode == 1) {
				tempshort |= 0x3b0;
			}
		}
	}else if(phylinkstatus1 & GMII_ANLPAR_10TFD) {
	/* 10 full duplex */
		media = MEDIUM_FULL_DUPLEX_MODE | MEDIUM_ENABLE_RECEIVE;
		if(ax178dataptr->PhyMode == PHY_MODE_MARVELL){
			if(ax178dataptr->LedMode == 1){
				tempshort |= 0x2f0;
			}
		}
	}else{
		/* 10 half duplex*/
		media = MEDIUM_ENABLE_RECEIVE;
		fullduplex=0;
		if(ax178dataptr->PhyMode == PHY_MODE_MARVELL){
			if(ax178dataptr->LedMode == 1){
				tempshort |= 0x02f0;
			}
		}
	}

	if(ax178dataptr->PhyMode == PHY_MODE_MARVELL){
		if(ax178dataptr->LedMode == 1){
			data16 = le16_to_cpu(tempshort);
		     if ( (ret = ax8817x_write_cmd (dev, AX_CMD_WRITE_MII_REG,
					(u8)dev->mii.phy_id, MARVELL_MANUAL_LED,
					REG_LENGTH, &data16)) < 0){
			     dbg("error on writing MII register"
				 " 0x19 failed: %02x", ret);
			     return ret;
		     }
		}
	}
	media |= 0x0004;
	if(ax178dataptr->UseRgmii != 0)
		media |= 0x0008;
	if(fullduplex){
		media |= 0x0020;  //ebable tx flow control as default;
		media |= 0x0010;  //ebable rx flow control as default;
	}

	return media;
}

static int realtek_init(struct usbnet *dev)
{
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	struct ax88178_data *ax178dataptr = data->priv.ax178dataptr;
	u16 tmp, tmp1;
	int ret;

	if(ax178dataptr->UseGpio0)
		tmp = (AXGPIOS_GPO0 | AXGPIOS_GPO0EN);
	else /* !UseGpio0 */
		tmp = (AXGPIOS_GPO1 | AXGPIOS_GPO1EN);

	/* Power up PHY */
	if ((ret = ax8817x_write_cmd (dev, AX_CMD_WRITE_GPIOS,
			tmp, 0, 0, NULL)) < 0){
		dbg("write GPIO failed: %d", ret);
		return ret;
	}
	msleep(25);

	tmp1 = tmp | AXGPIOS_GPO2 | AXGPIOS_GPO2EN;
	if ((ret = ax8817x_write_cmd (dev, AX_CMD_WRITE_GPIOS,
			tmp1, 0, 0, NULL)) < 0){
		dbg("write GPIO failed: %d", ret);
		return ret;
	}
	msleep(25);

	tmp1 = tmp | AXGPIOS_GPO2EN;
	if ((ret = ax8817x_write_cmd (dev, AX_CMD_WRITE_GPIOS,
			tmp1, 0, 0, NULL)) < 0){
		dbg("write GPIO failed: %d", ret);
		return ret;
	}
	msleep(245);

	tmp1 = tmp | AXGPIOS_GPO2EN | AXGPIOS_GPO2;
	if ((ret = ax8817x_write_cmd (dev, AX_CMD_WRITE_GPIOS,
			tmp1, 0, 0, NULL)) < 0){
		dbg("write GPIO failed: %d", ret);
		return ret;
	}

	ax178dataptr->UseRgmii=1;

	ax8817x_mdio_write_le (dev->net, dev->mii.phy_id, MII_BMCR, BMCR_RESET);
	msleep (20);

	if (ax178dataptr->PhyMode == PHY_MODE_REALTEK_8211CL) {
		ax8817x_mdio_write_le (dev->net, dev->mii.phy_id, 0x1F, 0x0005);
		ax8817x_mdio_write_le (dev->net, dev->mii.phy_id, 0x0C, 0x0000);
		tmp = ax8817x_mdio_read_le (dev->net, dev->mii.phy_id, 0x01);
		ax8817x_mdio_write_le (dev->net,
			dev->mii.phy_id, 0x01, (tmp | 0x80));
		ax8817x_mdio_write_le (dev->net, dev->mii.phy_id, 0x1F, 0x0000);

		if (ax178dataptr->LedMode == 12) {
			/* Configure LED */
			ax8817x_mdio_write_le (dev->net,
				dev->mii.phy_id, 0x1F, 0x0002);
			ax8817x_mdio_write_le (dev->net,
				dev->mii.phy_id, 0x1A, 0x00CB);
			ax8817x_mdio_write_le (dev->net,
				dev->mii.phy_id, 0x1F, 0x0000);
		}
	}

	/* MII interface has been disabled by ax8817x_mdio_write_le */
	ax8817x_write_cmd (dev, AX_CMD_SET_SW_MII, 0x0000, 0, 0, NULL);

	return 0;
}

static int marevell_init(struct usbnet *dev)
{
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	struct ax88178_data *ax178dataptr = data->priv.ax178dataptr;
	u16 tmp,phyreg,PhyPatch,data16;
	int ret;

	if(ax178dataptr->UseGpio0)
	{
		if ((ret = ax8817x_write_cmd (dev, AX_CMD_WRITE_GPIOS,
				AXGPIOS_GPO0EN |AXGPIOS_RSE,0, 0, NULL)) < 0){
			dbg("write GPIO failed: %d", ret);
			return ret;
		}
		msleep(25);
		tmp = AXGPIOS_GPO2 | AXGPIOS_GPO2EN | AXGPIOS_GPO0EN;
		if ((ret = ax8817x_write_cmd (dev, AX_CMD_WRITE_GPIOS,
				tmp, 0, 0, NULL)) < 0){
			dbg("write GPIO failed: %d", ret);
			return ret;
		}
		msleep(25);
		tmp = AXGPIOS_GPO2EN | AXGPIOS_GPO0EN;
		if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_GPIOS,
				tmp, 0, 0, NULL)) < 0){
			dbg("write GPIO failed: %d", ret);
			return ret;
		}
		msleep(245);
		tmp = AXGPIOS_GPO2 | AXGPIOS_GPO2EN | AXGPIOS_GPO0EN;
		if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_GPIOS,
				tmp, 0, 0, NULL)) < 0){
			dbg("write GPIO failed: %d", ret);
			return ret;
		}	
		
	}
	else /* !UseGpio0 */
	{
		tmp = AXGPIOS_GPO1|AXGPIOS_GPO1EN | AXGPIOS_RSE;
		if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_GPIOS,
				tmp, 0, 0, NULL)) < 0){
			dbg("write GPIO failed: %d", ret);
			return ret;
		}
		if(ax178dataptr->LedMode != 1) //our new demo board
		{
			msleep(25);
			tmp = AXGPIOS_GPO1 | AXGPIOS_GPO1EN |
				AXGPIOS_GPO2EN | AXGPIOS_GPO2;
			if ((ret =ax8817x_write_cmd(dev, AX_CMD_WRITE_GPIOS,
					tmp, 0, 0, NULL)) < 0){
				dbg("write GPIO failed: %d", ret);
				return ret;
			}
			msleep(25);
			tmp = AXGPIOS_GPO2EN | AXGPIOS_GPO1 | AXGPIOS_GPO1EN;
			if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_GPIOS,
					tmp, 0, 0, NULL)) < 0){
				dbg("write GPIO failed: %d", ret);
				return ret;
			}
			msleep(245);
			tmp = AXGPIOS_GPO1 | AXGPIOS_GPO1EN |
			      AXGPIOS_GPO2 | AXGPIOS_GPO2EN;
			if ((ret = ax8817x_write_cmd (dev, AX_CMD_WRITE_GPIOS,
					tmp, 0, 0, NULL)) < 0){
				dbg("write GPIO failed: %d", ret);
				return ret;
			}
		}
		else if(ax178dataptr->LedMode == 1)  //bufflo old card
		{
			msleep(350);
			if ((ret = ax8817x_write_cmd (dev, AX_CMD_WRITE_GPIOS,
					AXGPIOS_GPO1EN, 0, 0, NULL)) < 0){
				dbg("write GPIO failed: %d", ret);
				return ret;
			}
			msleep(350);
			if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_GPIOS,
					AXGPIOS_GPO1 | AXGPIOS_GPO1EN,
					0, 0, NULL)) < 0){
				dbg("write GPIO failed: %d", ret);
				return ret;
			}
		}		
	}


	if((ret = ax8817x_read_cmd(dev, AX_CMD_READ_MII_REG, dev->mii.phy_id,
			PHY_MARVELL_STATUS, REG_LENGTH, &data16)) < 0){
	       dbg("read register reg 27 failed: %d", ret);
	       return ret;
	}    //read phy register

	phyreg = le16_to_cpu(data16);
	if(!(phyreg & MARVELL_STATUS_HWCFG)){
		ax178dataptr->UseRgmii=1;
		PhyPatch = MARVELL_CTRL_RXDELAY | MARVELL_CTRL_TXDELAY;
		data16 = cpu_to_le16(PhyPatch);
		if((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_MII_REG,
				dev->mii.phy_id, PHY_MARVELL_CTRL,
				REG_LENGTH, &data16)) < 0)
			return ret;
	}

	if(ax178dataptr->LedMode == 1){
		if((ret = ax8817x_read_cmd(dev, AX_CMD_READ_MII_REG,
				dev->mii.phy_id, MARVELL_LED_CTRL,
				REG_LENGTH, &data16))< 0)
			return ret;
		phyreg = le16_to_cpu(data16);
		phyreg &= 0xf8ff;
		phyreg |= (1+0x100);

		data16 = le16_to_cpu(phyreg);
		if((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_MII_REG,
				dev->mii.phy_id, MARVELL_LED_CTRL,
				REG_LENGTH,&data16))< 0)
			return ret;
		if((ret = ax8817x_read_cmd(dev,AX_CMD_READ_MII_REG,
				dev->mii.phy_id, MARVELL_LED_CTRL,
				REG_LENGTH, &data16))< 0)
			return ret;
		phyreg = le16_to_cpu(data16);
		phyreg &=0xfc0f;
	} else if(ax178dataptr->LedMode == 2){

		if((ret = ax8817x_read_cmd(dev, AX_CMD_READ_MII_REG,
				dev->mii.phy_id, MARVELL_LED_CTRL,
				REG_LENGTH, &data16))< 0)
			return ret;

		phyreg = le16_to_cpu(data16);
		phyreg &= 0xf886;
		phyreg |= (1+0x10+0x300);
		data16 = cpu_to_le16(phyreg);
		if((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_MII_REG,
				dev->mii.phy_id, MARVELL_LED_CTRL,
				REG_LENGTH,&data16))< 0)
			return ret;

	}else if(ax178dataptr->LedMode == 5){
		if((ret = ax8817x_read_cmd(dev, AX_CMD_READ_MII_REG,
				dev->mii.phy_id, MARVELL_LED_CTRL,
				REG_LENGTH, &data16))< 0)
			return ret;
		phyreg = le16_to_cpu(data16);
		phyreg &= 0xf8be;
		phyreg |= (1+0x40+0x300);
		data16 = cpu_to_le16(phyreg);
		if((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_MII_REG, 
				dev->mii.phy_id, MARVELL_LED_CTRL,
				REG_LENGTH, &data16))< 0)
			return ret;
	} else if (ax178dataptr->LedMode == 11) {
		phyreg = ax8817x_mdio_read_le (dev->net, dev->mii.phy_id, 24);
		ax8817x_mdio_write_le (dev->net,
			dev->mii.phy_id, 24, (phyreg | 0x4106));

		/* MII interface has been disabled by ax8817x_mdio_write_le */
		ax8817x_write_cmd (dev, AX_CMD_SET_SW_MII, 0x0000, 0, 0, NULL);
	}
	
	return 0;
}

static int cicada_init(struct usbnet *dev)
{

	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	struct ax88178_data *ax178dataptr = data->priv.ax178dataptr;
	u16 tmp, phyreg, i, data16;
	int ret;

	if(ax178dataptr->UseGpio0)
	{
		if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_GPIOS,
				AXGPIOS_GPO0 | AXGPIOS_GPO0EN | AXGPIOS_RSE,
				0, 0, NULL)) < 0){
			dbg("write GPIO failed: %d", ret);
			return ret;
		}
	}
	else
	{
		tmp = AXGPIOS_GPO1|AXGPIOS_GPO1EN | AXGPIOS_RSE;
		if ((ret =ax8817x_write_cmd(dev, AX_CMD_WRITE_GPIOS,
				tmp,0,0,NULL)) < 0) {
			dbg("write GPIO failed: %d", ret);
			return ret;
		}
		if(ax178dataptr->LedMode!= 1) //our new demo board
		{
			msleep(25);
			tmp = AXGPIOS_GPO1 | AXGPIOS_GPO1EN | 
			      AXGPIOS_GPO2EN | AXGPIOS_GPO2;
			if ((ret =ax8817x_write_cmd(dev, AX_CMD_WRITE_GPIOS,
					tmp,0,0,NULL)) < 0) {
				dbg("write GPIO failed: %d", ret);
				return ret;
			}
			msleep(25);
			tmp = AXGPIOS_GPO2EN | AXGPIOS_GPO1 | AXGPIOS_GPO1EN;
			if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_GPIOS,
					tmp, 0, 0, NULL)) < 0) {
				dbg("write GPIO failed: %d", ret);
				return ret;
			}
			msleep(245);
			tmp = AXGPIOS_GPO1 | AXGPIOS_GPO1EN | 
			      AXGPIOS_GPO2 | AXGPIOS_GPO2EN;
			if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_GPIOS,
					tmp,0,0,NULL)) < 0) {
				dbg("write GPIO failed: %d", ret);
				return ret;
			}
		}
		else if(ax178dataptr->LedMode==1)  //bufflo old card
		{
			msleep(350);
			if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_GPIOS, 
					AXGPIOS_GPO1EN, 0, 0, NULL)) < 0) {
				dbg("write GPIO failed: %d", ret);
				return ret;
			}
			msleep(350);
			if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_GPIOS, 
					AXGPIOS_GPO1|AXGPIOS_GPO1EN, 
					0, 0, NULL)) < 0) {
				dbg("write GPIO failed: %d", ret);
				return ret;
			}
		}
	}

	if(ax178dataptr->PhyMode == PHY_MODE_CICADA_FAMILY) {
	//CICADA 1st version phy
		ax178dataptr->UseRgmii=1;

		for (i = 0; i < (sizeof(CICADA_FAMILY_HWINIT) / 
			 	 sizeof(CICADA_FAMILY_HWINIT[0])); i++) {
			data16 = cpu_to_le16(CICADA_FAMILY_HWINIT[i].value);
			ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_MII_REG, 
					dev->mii.phy_id, 
					CICADA_FAMILY_HWINIT[i].offset, 
					REG_LENGTH, &data16);
			if(ret < 0) return ret;
		}
	}
	else if(ax178dataptr->PhyMode == PHY_MODE_CICADA_V2){
		ax178dataptr->UseRgmii=1;

		for (i = 0; i < (sizeof(CICADA_V2_HWINIT) / 
				 sizeof(CICADA_V2_HWINIT[0])); i++) {
			data16 = cpu_to_le16(CICADA_V2_HWINIT[i].value);
			ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_MII_REG, 
					dev->mii.phy_id,
					CICADA_V2_HWINIT[i].offset,
					REG_LENGTH, &data16);
			if(ret < 0) return ret;
		}
	}
	else if(ax178dataptr->PhyMode == PHY_MODE_CICADA_V2_ASIX){
		ax178dataptr->UseRgmii=1;

		for (i = 0; i < (sizeof(CICADA_V2_ASIX_HWINIT) /
				 sizeof(CICADA_V2_ASIX_HWINIT[0])); i++) {
			data16 = cpu_to_le16(CICADA_V2_ASIX_HWINIT[i].value);
			ret=ax8817x_write_cmd(dev, AX_CMD_WRITE_MII_REG,
					dev->mii.phy_id,
					CICADA_V2_ASIX_HWINIT[i].offset,
					REG_LENGTH, &data16);
			if(ret < 0) return ret;
		}
	}

	if(ax178dataptr->PhyMode == PHY_MODE_CICADA_FAMILY){
		if(ax178dataptr->LedMode == 3){
			if((ret = ax8817x_read_cmd(dev,AX_CMD_READ_MII_REG, 
					dev->mii.phy_id, 27, 2, &data16))< 0)
				return ret;
			phyreg = le16_to_cpu(data16);
			phyreg &= 0xfcff;
			phyreg |= 0x0100;
			data16 = cpu_to_le16(phyreg);
			if((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_MII_REG, 
					dev->mii.phy_id, 27,2,&data16))< 0)
				return ret;
		}
	}

	return 0;
}

static int agere_init(struct usbnet *dev)
{
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	struct ax88178_data *ax178dataptr = data->priv.ax178dataptr;
	u16 tmp, phyreg, i;
	int ret;

	if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_GPIOS,
			AXGPIOS_GPO1 | AXGPIOS_GPO1EN | AXGPIOS_RSE,
			0, 0, NULL)) < 0){
		dbg("write GPIO failed: %d", ret);
		return ret;
	}
	msleep(25);
	if ((ret=ax8817x_write_cmd(dev, AX_CMD_WRITE_GPIOS, 
			(AXGPIOS_GPO1 | AXGPIOS_GPO1EN | 
			AXGPIOS_GPO2EN | AXGPIOS_GPO2),
			0,0,NULL)) < 0){
		dbg("write GPIO failed: %d", ret);
		return ret;
	}
	msleep(25);
	if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_GPIOS,
			AXGPIOS_GPO2EN | AXGPIOS_GPO1 | AXGPIOS_GPO1EN, 
			0, 0, NULL)) < 0){
		dbg("write GPIO failed: %d", ret);
		return ret;
	}
	msleep(245);
	if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_GPIOS,
			(AXGPIOS_GPO1 | AXGPIOS_GPO1EN |
			AXGPIOS_GPO2 | AXGPIOS_GPO2EN), 0, 0, NULL)) < 0){
		dbg("write GPIO failed: %d", ret);
		return ret;
	}
	
	ax178dataptr->UseRgmii=1;

	phyreg = cpu_to_le16(BMCR_RESET);
	if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_MII_REG,
			dev->mii.phy_id, MII_BMCR, REG_LENGTH, &phyreg)) < 0) {
		dbg("Failed to write MII reg - MII_BMCR: %02x", ret);
		return ret;
	} //software reset

	while (1)
	{
		phyreg = cpu_to_le16(0x1001);
		ax8817x_write_cmd(dev, AX_CMD_WRITE_MII_REG, 
			dev->mii.phy_id, 21, REG_LENGTH, &phyreg);
		msleep(10);
		ax8817x_read_cmd(dev, AX_CMD_READ_MII_REG, 
			dev->mii.phy_id, 21, REG_LENGTH, &phyreg);
		tmp = le16_to_cpu(phyreg);
		if ((tmp & 0xf00f) == 0x1001)
			break;
		msleep(10);
	}

	if (ax178dataptr->LedMode == 4)
	{
		phyreg = cpu_to_le16(0x7417);
		ax8817x_write_cmd(dev, AX_CMD_WRITE_MII_REG, 
			dev->mii.phy_id, 28, 2, &phyreg);
	}
	else if (ax178dataptr->LedMode == 9)
	{
		phyreg = cpu_to_le16(0x7a10);
		ax8817x_write_cmd(dev, AX_CMD_WRITE_MII_REG, 
			dev->mii.phy_id, 28, 2, &phyreg);
	}
	else if (ax178dataptr->LedMode == 10)
	{
		phyreg = cpu_to_le16(0x7a13);
		ax8817x_write_cmd(dev, AX_CMD_WRITE_MII_REG, 
			dev->mii.phy_id, 28, 2, &phyreg);
	}

	for (i = 0; i < (sizeof(AGERE_FAMILY_HWINIT) /
			 sizeof(AGERE_FAMILY_HWINIT[0])); i++) {
		phyreg = cpu_to_le16(AGERE_FAMILY_HWINIT[i].value);
		ret=ax8817x_write_cmd(dev, AX_CMD_WRITE_MII_REG, 
			dev->mii.phy_id, AGERE_FAMILY_HWINIT[i].offset,
			REG_LENGTH, &phyreg);
		if(ret < 0) return ret;
	}

	return 0;
}

static int phy_init(struct usbnet *dev)
{
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	struct ax88178_data *ax178dataptr = data->priv.ax178dataptr;
	int ret;
	u16 tmp, data16, phyanar, phyauxctrl, phyctrl, phyreg = 0;

	if(ax178dataptr->PhyMode == PHY_MODE_MARVELL) {
		if((ret = marevell_init(dev)) < 0) return ret;
	}else if(ax178dataptr->PhyMode == PHY_MODE_CICADA_FAMILY) {
		if((ret = cicada_init(dev)) < 0) return ret;
	}else if(ax178dataptr->PhyMode == PHY_MODE_CICADA_V1) {
		if((ret = cicada_init(dev)) < 0) return ret;
	}else if(ax178dataptr->PhyMode == PHY_MODE_CICADA_V2_ASIX) {
		if((ret = cicada_init(dev)) < 0) return ret;
	}else if(ax178dataptr->PhyMode == PHY_MODE_AGERE_FAMILY) {
		if((ret = agere_init(dev)) < 0) return ret;
	} else if ((ax178dataptr->PhyMode >= PHY_MODE_REALTEK_8211CL) &&
			(ax178dataptr->PhyMode <= PHY_MODE_REALTEK_8251CL)) {
		if ((ret = realtek_init (dev)) < 0) return ret;
	}

	if(ax178dataptr->PhyMode != PHY_MODE_AGERE_FAMILY)
	{
		/* reset phy */
		data16 = cpu_to_le16(BMCR_RESET);
		if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_MII_REG, 
				dev->mii.phy_id, MII_BMCR, 
				REG_LENGTH, (void *)(&data16))) < 0) {
			dbg("Failed to write MII reg - MII_BMCR: %02x", ret);
			return ret;
		}
	}

	if  ((ret = ax8817x_read_cmd(dev, AX_CMD_READ_MII_REG, 
			dev->mii.phy_id , MII_BMCR, REG_LENGTH, &data16)) < 0) {
		dbg("error on read MII reg - MII_BMCR: %02x", ret);
		return ret;   //could be 0x0000
	}

	phyctrl = le16_to_cpu(data16);
	tmp=phyctrl;
	phyctrl &=~(BMCR_PDOWN|BMCR_ISOLATE);
	if(phyctrl != tmp){
		data16 = cpu_to_le16(phyctrl);
		if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_MII_REG, 
				dev->mii.phy_id, MII_BMCR,
				REG_LENGTH, &data16)) < 0) {
			dbg("Failed to write MII reg - MII_BMCR: %02x", ret);
			return ret;
		}

	}

	phyctrl&= ~BMCR_ISOLATE;
	phyanar= 1 | (0x0400 | ADVERTISE_100FULL | ADVERTISE_100HALF |
		      ADVERTISE_10FULL|ADVERTISE_10HALF);
	phyauxctrl=0x0200; //1000M and full duplex

	data16 = cpu_to_le16(phyanar);
	if((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_MII_REG, dev->mii.phy_id,
		GMII_PHY_ANAR,REG_LENGTH, &data16))< 0)
		return ret;

	data16 = cpu_to_le16(phyauxctrl);
	if((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_MII_REG, dev->mii.phy_id,
		GMII_PHY_1000BT_CONTROL,REG_LENGTH, &data16)) < 0)
			return ret;

	phyctrl |= (BMCR_ANENABLE|BMCR_ANRESTART);
	data16 = cpu_to_le16(phyctrl);
	if((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_MII_REG, dev->mii.phy_id,
		GMII_PHY_CONTROL, REG_LENGTH, &data16))< 0)
			return ret;

	if(ax178dataptr->PhyMode == PHY_MODE_MARVELL){
		if(ax178dataptr->LedMode==1) {
			phyreg |= 0x3f0;
			data16 = cpu_to_le16(phyreg);
			if((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_MII_REG,
					dev->mii.phy_id, 
					25, REG_LENGTH, &phyreg)) < 0)
				return ret;
		}
	}

	msleep(3000);

	if ((ret = ax8817x_write_cmd(dev, AX_CMD_SET_HW_MII, 
			0, 0, 0, NULL)) < 0) {
		dbg("disable PHY access failed: %d", ret);
		return ret;
	}

	return 0;	

}

static int ax88178_bind(struct usbnet *dev, struct usb_interface *intf)
{
	int ret;
	void *buf;
	u16 EepromData, PhyID, temp16;
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	struct ax88178_data *ax178dataptr;

	usbnet_get_endpoints(dev,intf);

	buf = kmalloc(6, GFP_KERNEL);
	if(!buf) {
		dbg ("Cannot allocate memory for buffer");
		ret = -ENOMEM;
		goto error_out;
	}

	/* allocate 178 data */
	if (!(ax178dataptr = kmalloc (sizeof (*ax178dataptr), GFP_KERNEL))) {
		dbg ("Cannot allocate memory for AX88178 data");
		ret = -ENOMEM;
		goto error_out;
	}
	memset (ax178dataptr, 0, sizeof (struct ax88178_data));
	data->priv.ax178dataptr = ax178dataptr;
	/* end of allocate 178 data */

	if ((ret = ax8817x_write_cmd(dev, 0x22, 0x0000, 0, 0, buf)) < 0) {
		dbg("write S/W reset failed: %d", ret);
		goto error_out;
	}
	msleep(150);

	if ((ret = ax8817x_write_cmd(dev, 0x20, 0x0048, 0, 0, buf)) < 0) {
		dbg("write S/W reset failed: %d", ret);
		goto error_out;
	}
	msleep(150);

	if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_RX_CTL,
			AX_RX_CTL_STOP, 0, 0, buf)) < 0) {
		dbg("send AX_CMD_WRITE_RX_CTL failed: %d", ret);
		goto error_out;
	}

	msleep(150);

	/* Get the MAC address */
	memset(buf, 0, ETH_ALEN);
	if ((ret = ax8817x_read_cmd (dev, AX88772_CMD_READ_NODE_ID,
				     0, 0, ETH_ALEN, buf)) < 0) {
		dbg("read AX_CMD_READ_NODE_ID failed: %d", ret);
		goto error_out;
	}
	memcpy(dev->net->dev_addr, buf, ETH_ALEN);
	/* End of get MAC address */

	/* Get the EEPROM data*/
	if ((ret = ax8817x_read_cmd (dev, AX_CMD_READ_EEPROM, 0x0017,
				     0, 2, (void *)(&EepromData))) < 0) {
		dbg("read SROM address 17h failed: %d", ret);
		goto error_out;
	}
	ax178dataptr->EepromData = le16_to_cpu(EepromData);
	/* End of get EEPROM data */

	/* OpenTablet7 MAC-to MAC mode */
	if (ax178dataptr->EepromData == 0x7C) {
		u16 media;

		/* Force media link at giga mode */
		media = MEDIUM_GIGA_MODE |
			MEDIUM_FULL_DUPLEX_MODE |
			MEDIUM_ENABLE_125MHZ |
			MEDIUM_ENABLE_RECEIVE |
			MEDIUM_ENABLE_RX_FLOWCTRL |
			MEDIUM_ENABLE_TX_FLOWCTRL;

		if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_MEDIUM_MODE,
				media, 0, 0, buf)) < 0) {
			dbg("write mode medium reg failed: %d", ret);
			goto error_out;
		}

		goto skip_init_phy;
	}

	/* Get PHY id */

	if ((ret = ax8817x_write_cmd (dev, AX_CMD_SET_SW_MII,
				      0x0000, 0, 0, buf)) < 0) {
		dbg("enable PHY reg. access capability: %d", ret);
		goto error_out;
	}

	if ((ret = ax8817x_read_cmd(dev, AX_CMD_READ_PHY_ID,
				    0, 0, REG_LENGTH, &temp16)) < 0) {
		dbg("error on read AX_CMD_READ_PHY_ID: %02x", ret);
		goto error_out;
	} else if (ret < 2) {
		/* this should always return 2 bytes */
		dbg("AX_CMD_READ_PHY_ID returned less than 2 bytes: ret=%02x",
			ret);
		ret = -EIO;
		goto error_out;
	}

	PhyID = le16_to_cpu(temp16) >> 8;
	/* End of get PHY id */

	/* Initialize MII structure */
	dev->mii.dev = dev->net;
	dev->mii.mdio_read = ax8817x_mdio_read_le;
	dev->mii.mdio_write = ax8817x_mdio_write_le;
	dev->mii.phy_id_mask = 0x3f;
	dev->mii.reg_num_mask = 0x1f;
	dev->mii.phy_id = (u8)(PhyID & PHY_ID_MASK);

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,29)
	dev->net->do_ioctl = ax8817x_ioctl;
	dev->net->set_multicast_list = ax8817x_set_multicast;
	dev->net->set_mac_address = ax8817x_set_mac_addr;
#else
	dev->net->netdev_ops = &ax88x72_netdev_ops;
#endif
	dev->net->ethtool_ops = &ax8817x_ethtool_ops;

	/* Register suspend and resume functions */
	data->suspend = ax88772_suspend;
	data->resume = ax88772_resume;

	if (ax178dataptr->EepromData == 0xffff)
	{
		ax178dataptr->PhyMode  = PHY_MODE_MARVELL;
		ax178dataptr->LedMode  = 0;
		ax178dataptr->UseGpio0 = 1; //True
	}
	else
	{
		ax178dataptr->PhyMode = (u8)(ax178dataptr->EepromData & 
						EEPROMMASK);
		ax178dataptr->LedMode = (u8)(ax178dataptr->EepromData >> 8);	
		if(ax178dataptr->EepromData & 0x80) {
			ax178dataptr->UseGpio0=0; //MARVEL se and other
		}
		else {
			ax178dataptr->UseGpio0=1; //cameo
		}
	}

	ret = phy_init(dev);

skip_init_phy:
	if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_IPG0,
			(AX88772_IPG0_DEFAULT | AX88772_IPG1_DEFAULT << 8),
			0x000e, 0, NULL)) < 0) {
		dbg("write IPG IPG1 IPG2 reg failed: %d", ret);
		goto error_out;
	}

	if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_RX_CTL,
			(AX_RX_CTL_MFB | AX_RX_CTL_START | AX_RX_CTL_AB),
			0, 0, NULL)) < 0) {
		dbg("write RX ctrl reg failed: %d", ret);
		goto error_out;
	}

	if (dev->driver_info->flags & FLAG_FRAMING_AX) {
		dev->rx_urb_size = 16384;
	}

error_out:
	kfree (buf);
	if (!ret)
		printk (version);

	return ret;
}

static int ax88772_rx_fixup(struct usbnet *dev, struct sk_buff *skb)
{
	u8  *head;
	u32  header;
	char *packet;
	struct sk_buff *ax_skb;
	u16 size;

	head = (u8 *) skb->data;
	memcpy(&header, head, sizeof(header));
	le32_to_cpus(&header);
	packet = head + sizeof(header);

	skb_pull(skb, 4);

	while (skb->len > 0) {
		if ((short)(header & 0x0000ffff) !=
		    ~((short)((header & 0xffff0000) >> 16))) {
			netdev_dbg(dev->net,"header length data is error");
		}
		/* get the packet length */
		size = (u16) (header & 0x0000ffff);

		if ((skb->len) - ((size + 1) & 0xfffe) == 0) {
			skb->truesize = size + sizeof(struct sk_buff);
			return 2;
		}

		if (size > ETH_FRAME_LEN) {
			netdev_dbg(dev->net,"invalid rx length %d", size);
			return 0;
		}
		ax_skb = skb_clone(skb, GFP_ATOMIC);
		if (ax_skb) {
			ax_skb->data = packet;
			__pskb_trim (ax_skb, size);
			ax_skb->truesize = size + sizeof(struct sk_buff);
			usbnet_skb_return(dev, ax_skb);
		} else {
			return 0;
		}

		skb_pull(skb, (size + 1) & 0xfffe);

		if (skb->len == 0)
			break;

		head = (u8 *) skb->data;
		memcpy(&header, head, sizeof(header));
		le32_to_cpus(&header);
		packet = head + sizeof(header);
		skb_pull(skb, 4);
	}

	if (skb->len < 0) {
		netdev_dbg(dev->net,"invalid rx length %d", skb->len);
		return 0;
	}
	return 1;
}

static struct sk_buff *ax88772_tx_fixup(struct usbnet *dev, struct sk_buff *skb, unsigned flags)
{
	int padlen;
	int headroom = skb_headroom(skb);
	int tailroom = skb_tailroom(skb);
	u32 packet_len;
	u32 padbytes = 0xffff0000;

	padlen = ((skb->len + 4) % 512) ? 0 : 4;

	if ((!skb_cloned(skb))
	    && ((headroom + tailroom) >= (4 + padlen))) {
		if ((headroom < 4) || (tailroom < padlen)) {
			skb->data = memmove(skb->head + 4, skb->data, skb->len);
			__pskb_trim (skb, skb->len);
		}
	} else {
		struct sk_buff *skb2;
		skb2 = skb_copy_expand(skb, 4, padlen, flags);
		dev_kfree_skb_any(skb);
		skb = skb2;
		if (!skb)
			return NULL;
	}

	skb_push(skb, 4);
	packet_len = (((skb->len - 4) ^ 0x0000ffff) << 16) + (skb->len - 4);
	cpu_to_le32s(&packet_len);
	memcpy(skb->data, &packet_len, sizeof(packet_len));

	if ((skb->len % 512) == 0) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
		memcpy(skb->tail, &padbytes, sizeof(padbytes));
#else
		memcpy(skb_tail_pointer(skb), &padbytes, sizeof(padbytes));
#endif
		skb_put(skb, sizeof(padbytes));
	}
	return skb;
}

static void
ax88772b_rx_checksum (struct sk_buff *skb, struct ax88772b_rx_header *rx_hdr)
{
	skb->ip_summed = CHECKSUM_NONE;

#if defined(AX_PARTIAL_CSUM)
	skb->csum = le16_to_cpu (rx_hdr->csum);
	#if (LINUX_VERSION_CODE < KERNEL_VERSION(2,6,19))
	skb->ip_summed = CHECKSUM_HW;
	#else
	skb->ip_summed = CHECKSUM_COMPLETE;
	#endif
#else
	/* checksum error bit is set */
	if (rx_hdr->l3_csum_err || rx_hdr->l4_csum_err) {
		return;
	}

	/* It must be a TCP or UDP packet with a valid checksum */
	if ((rx_hdr->l4_type == AX_RXHDR_L4_TYPE_TCP) ||
	    (rx_hdr->l4_type == AX_RXHDR_L4_TYPE_UDP)) {
		skb->ip_summed = CHECKSUM_UNNECESSARY;
	}
#endif
}

static int ax88772b_rx_fixup(struct usbnet *dev, struct sk_buff *skb)
{
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	struct ax88772b_data *ax772b_data = data->priv.ax772b_data;
	struct ax88772b_rx_header *rx_hdr;
	struct sk_buff *ax_skb;

	while (skb->len > 0) {

		rx_hdr = (struct ax88772b_rx_header *)skb->data;

		if ((short)rx_hdr->len != (~((short)rx_hdr->len_bar) & 0x7FF)) {
			return 0;
		}

		if (rx_hdr->len > (ETH_FRAME_LEN + 4)) {
			netdev_dbg(dev->net,"invalid rx length %d", rx_hdr->len);
			return 0;
		}

		if (skb->len -
			((rx_hdr->len + sizeof (*rx_hdr) + 3) & 0xfffc) == 0) {
			skb_pull(skb, sizeof (*rx_hdr));
			__pskb_trim (skb, rx_hdr->len);
			skb->len = rx_hdr->len;
			skb->truesize = rx_hdr->len + sizeof(struct sk_buff);
			if (ax772b_data->checksum & AX_RX_CHECKSUM) {
				ax88772b_rx_checksum (skb, rx_hdr);
			}
			return 2;
		}

		ax_skb = skb_clone(skb, GFP_ATOMIC);
		if (ax_skb) {
			ax_skb->len = rx_hdr->len;
			ax_skb->data = skb->data + sizeof (*rx_hdr);
			__pskb_trim(ax_skb, rx_hdr->len);
			ax_skb->truesize = rx_hdr->len + sizeof(struct sk_buff);
			if (ax772b_data->checksum & AX_RX_CHECKSUM) {
				ax88772b_rx_checksum (ax_skb, rx_hdr);
			}
			usbnet_skb_return(dev, ax_skb);

		} else {
			return 0;
		}

		skb_pull(skb, ((rx_hdr->len + sizeof (*rx_hdr) + 3) & 0xfffc));

		if (skb->len == 0)
			break;
	}

	if (skb->len < 0) {
		netdev_dbg(dev->net,"invalid rx length %d", skb->len);
		return 0;
	}
	return 1;
}

static struct sk_buff *ax88772b_tx_fixup(struct usbnet *dev, struct sk_buff *skb, unsigned flags)
{
	int padlen;
	int headroom = skb_headroom(skb);
	int tailroom = skb_tailroom(skb);
	u32 packet_len;
	u32 padbytes = 0xffff0000;

	padlen = ((skb->len + 4) % 512) ? 0 : 4;

	if ((!skb_cloned(skb))
	    && ((headroom + tailroom) >= (4 + padlen))) {
		if ((headroom < 4) || (tailroom < padlen)) {
			skb->data = memmove(skb->head + 4, skb->data, skb->len);
			__pskb_trim (skb, skb->len);
		}
	} else {
		struct sk_buff *skb2;
		skb2 = skb_copy_expand(skb, 4, padlen, flags);
		dev_kfree_skb_any(skb);
		skb = skb2;
		if (!skb)
			return NULL;
	}

	skb_push(skb, 4);
	packet_len = (((skb->len - 4) ^ 0x0000ffff) << 16) + (skb->len - 4);
	if (skb->ip_summed == CHECKSUM_NONE) {
		packet_len |= AX_TX_HDR_DICF;
	}
	le32_to_cpus(&packet_len);
	memcpy(skb->data, &packet_len, sizeof(packet_len));

	if ((skb->len % 512) == 0) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,22)
		memcpy(skb->tail, &padbytes, sizeof(padbytes));
#else
		memcpy(skb_tail_pointer(skb), &padbytes, sizeof(padbytes));
#endif
		skb_put(skb, sizeof(padbytes));
	}
	return skb;
}

static const u8 ChkCntSel [6][3] = 
{
	{12, 23, 31},
	{12, 31, 23},
	{23, 31, 12},
	{23, 12, 31},
	{31, 12, 23},
	{31, 23, 12}
};

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static void ax88772_link_reset (void *data)
{
	struct usbnet *dev = (struct usbnet *)data;
	struct ax8817x_data *ax17x_data = (struct ax8817x_data *)&dev->data;
	struct ax88772_data *ax772_data = ax17x_data->priv.ax772_data;
#else
static void ax88772_link_reset (struct work_struct *work)
{
	struct ax88772_data *ax772_data = container_of (work, 
					struct ax88772_data, check_link);
	struct usbnet *dev = ax772_data->dev;
#endif
	
	if (ax772_data->Event == AX_SET_RX_CFG) {
		u16 bmcr;
		u16 mode;
		
		ax772_data->Event = AX_NOP;
	
		mode = AX88772_MEDIUM_DEFAULT;

		bmcr = ax8817x_mdio_read_le(dev->net, 
				dev->mii.phy_id, MII_BMCR);
		if (!(bmcr & BMCR_FULLDPLX))
			mode &= ~AX88772_MEDIUM_FULL_DUPLEX;
		if (!(bmcr & BMCR_SPEED100))
			mode &= ~AX88772_MEDIUM_100MB;

		ax8817x_write_cmd(dev, AX_CMD_WRITE_MEDIUM_MODE, 
			mode, 0, 0, NULL);
		return;
	}
	
	switch (ax772_data->Event) {
	  case WAIT_AUTONEG_COMPLETE:
		if (jiffies > (ax772_data->autoneg_start + 5 * HZ)) {
			ax772_data->Event = PHY_POWER_DOWN;
			ax772_data->TickToExpire = 23;
		}
		break;
	  case PHY_POWER_DOWN:
		if (ax772_data->TickToExpire == 23) {
			/* Set Phy Power Down */
			ax8817x_write_cmd(dev, AX_CMD_SW_RESET,
					  AX_SWRESET_IPPD,
					  0, 0, NULL);
			--ax772_data->TickToExpire;
		} else if (--ax772_data->TickToExpire == 0) {
			/* Set Phy Power Up */
			ax8817x_write_cmd(dev, AX_CMD_SW_RESET,
				AX_SWRESET_IPRL, 0, 0, NULL);
			ax8817x_write_cmd(dev, AX_CMD_SW_RESET,
				AX_SWRESET_IPPD | AX_SWRESET_IPRL, 0, 0, NULL);
			msleep(10);
			ax8817x_write_cmd(dev, AX_CMD_SW_RESET,
				AX_SWRESET_IPRL, 0, 0, NULL);
			msleep(60);
			ax8817x_write_cmd(dev, AX_CMD_SW_RESET,
				AX_SWRESET_CLEAR, 0, 0, NULL);
			ax8817x_write_cmd(dev, AX_CMD_SW_RESET,
				AX_SWRESET_IPRL, 0, 0, NULL);

			ax8817x_mdio_write_le(dev->net, dev->mii.phy_id, 
				MII_ADVERTISE,
				ADVERTISE_ALL | ADVERTISE_CSMA | 
				ADVERTISE_PAUSE_CAP);
			mii_nway_restart(&dev->mii);
			
			ax772_data->Event = PHY_POWER_UP;
			ax772_data->TickToExpire = 47;
		}
		break;
	  case PHY_POWER_UP:
		if (--ax772_data->TickToExpire == 0) {
			ax772_data->Event = PHY_POWER_DOWN;
			ax772_data->TickToExpire = 23;
		}
		break;
	  default:
		break;
	}
	return;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static void ax88772a_link_reset (void *data)
{
	struct usbnet *dev = (struct usbnet *)data;
	struct ax8817x_data *ax17x_data = (struct ax8817x_data *)&dev->data;
	struct ax88772a_data *ax772a_data = ax17x_data->priv.ax772a_data;
#else
static void ax88772a_link_reset (struct work_struct *work)
{
	struct ax88772a_data *ax772a_data = container_of (work, 
					struct ax88772a_data, check_link);
	struct usbnet *dev = ax772a_data->dev;
#endif
	int PowSave = (ax772a_data->EepromData >> 14);
	u16 phy_reg;
	
	if (ax772a_data->Event == AX_SET_RX_CFG) {
		u16 bmcr;
		u16 mode;

		ax772a_data->Event = AX_NOP;
	
		mode = AX88772_MEDIUM_DEFAULT;

		bmcr = ax8817x_mdio_read_le(dev->net, 
				dev->mii.phy_id, MII_BMCR);
		if (!(bmcr & BMCR_FULLDPLX))
			mode &= ~AX88772_MEDIUM_FULL_DUPLEX;
		if (!(bmcr & BMCR_SPEED100))
			mode &= ~AX88772_MEDIUM_100MB;

		ax8817x_write_cmd(dev, AX_CMD_WRITE_MEDIUM_MODE, 
			mode, 0, 0, NULL);
		return;
	}

	switch (ax772a_data->Event) {
	case WAIT_AUTONEG_COMPLETE:
		if (jiffies > (ax772a_data->autoneg_start + 5 * HZ)) {
			ax772a_data->Event = CHK_CABLE_EXIST;
			ax772a_data->TickToExpire = 14;
		}
		break;
	case CHK_CABLE_EXIST:
		phy_reg = ax8817x_mdio_read_le(dev->net, dev->mii.phy_id, 0x12);
		if ((phy_reg != 0x8012) && (phy_reg != 0x8013)) {
			ax8817x_mdio_write_le(dev->net,
				dev->mii.phy_id, 0x16, 0x4040);
			mii_nway_restart(&dev->mii);
			ax772a_data->Event = CHK_CABLE_STATUS;
			ax772a_data->TickToExpire = 31;
		} else if (--ax772a_data->TickToExpire == 0) {
			mii_nway_restart(&dev->mii);
			ax772a_data->Event = CHK_CABLE_EXIST_AGAIN;
			if (PowSave == 0x03){
			  ax772a_data->TickToExpire = 47;
			} else if (PowSave == 0x01) {
			  ax772a_data->DlyIndex = (u8)(jiffies % 6);
			  ax772a_data->DlySel = 0;
			  ax772a_data->TickToExpire = 
			  ChkCntSel[ax772a_data->DlyIndex][ax772a_data->DlySel];
			}
		}
		break;
	case CHK_CABLE_EXIST_AGAIN:
		/* if cable disconnected */
		phy_reg = ax8817x_mdio_read_le(dev->net, dev->mii.phy_id, 0x12);
		if ((phy_reg != 0x8012) && (phy_reg != 0x8013)) {
			mii_nway_restart(&dev->mii);
			ax772a_data->Event = CHK_CABLE_STATUS;
			ax772a_data->TickToExpire = 31;
		} else if (--ax772a_data->TickToExpire == 0) {
			/* Power down PHY */
			ax8817x_write_cmd(dev, AX_CMD_SW_RESET,
					  AX_SWRESET_IPPD,
					  0, 0, NULL);
			ax772a_data->Event = PHY_POWER_DOWN;
			if (PowSave == 0x03){
			  ax772a_data->TickToExpire = 23;
			} else if (PowSave == 0x01) {
			  ax772a_data->TickToExpire = 31;
			}
		}
		break;
	case PHY_POWER_DOWN:
		if (--ax772a_data->TickToExpire == 0) {
			ax772a_data->Event = PHY_POWER_UP;
		}
		break;
	case CHK_CABLE_STATUS:
		if (--ax772a_data->TickToExpire == 0) {
			ax8817x_mdio_write_le(dev->net,
					dev->mii.phy_id, 0x16, 0x4040);
			mii_nway_restart(&dev->mii);
			ax772a_data->Event = CHK_CABLE_EXIST_AGAIN;
			if (PowSave == 0x03){
			  ax772a_data->TickToExpire = 47;
			} else if (PowSave == 0x01) {
			  ax772a_data->DlyIndex = (u8)(jiffies % 6);
			  ax772a_data->DlySel = 0;
			  ax772a_data->TickToExpire = 
			    ChkCntSel[ax772a_data->DlyIndex][ax772a_data->DlySel];
			}
		}
		break;
	case PHY_POWER_UP:

		ax88772a_phy_powerup (dev);

		ax8817x_mdio_write_le(dev->net, dev->mii.phy_id, MII_ADVERTISE,
			ADVERTISE_ALL | ADVERTISE_CSMA | ADVERTISE_PAUSE_CAP);

		mii_nway_restart(&dev->mii);

		ax772a_data->Event = CHK_CABLE_EXIST_AGAIN;

		if (PowSave == 0x03){
			  ax772a_data->TickToExpire = 47;
			  
		} else if (PowSave == 0x01) {
		  
		  if (++ax772a_data->DlySel >= 3) {
		    ax772a_data->DlyIndex = (u8)(jiffies % 6);
		    ax772a_data->DlySel = 0;
		  }  
		  ax772a_data->TickToExpire = 
			ChkCntSel[ax772a_data->DlyIndex][ax772a_data->DlySel];
		}
		break;
	default:
		break;
	}

	return;
}

#if LINUX_VERSION_CODE < KERNEL_VERSION(2,6,20)
static void ax88772b_link_reset (void *data)
{
	struct usbnet *dev = (struct usbnet *)data;
	struct ax8817x_data *ax17x_data = (struct ax8817x_data *)&dev->data;
	struct ax88772b_data *ax772b_data = ax17x_data->priv.ax772b_data;
#else
static void ax88772b_link_reset (struct work_struct *work)
{
	struct ax88772b_data *ax772b_data = container_of (work, 
					struct ax88772b_data, check_link);
	struct usbnet *dev = ax772b_data->dev;
#endif

	switch (ax772b_data->Event) {

	case AX_SET_RX_CFG:
	{
		u16 bmcr = ax8817x_mdio_read_le(dev->net,
					dev->mii.phy_id, MII_BMCR);
		u16 mode = AX88772_MEDIUM_DEFAULT;

		if (!(bmcr & BMCR_FULLDPLX))
			mode &= ~AX88772_MEDIUM_FULL_DUPLEX;
		if (!(bmcr & BMCR_SPEED100))
			mode &= ~AX88772_MEDIUM_100MB;

		ax8817x_write_cmd(dev, AX_CMD_WRITE_MEDIUM_MODE, 
					mode, 0, 0, NULL);
		break;
	}
	case PHY_POWER_UP:
	{
		u16 tmp16;

		ax88772a_phy_powerup (dev);
		tmp16 = ax8817x_mdio_read_le(dev->net, dev->mii.phy_id, 0x12);
		ax8817x_mdio_write_le(dev->net, dev->mii.phy_id, 0x12,
				((tmp16 & 0xFF9F) | 0x0040));

		ax8817x_mdio_write_le(dev->net, dev->mii.phy_id, MII_ADVERTISE,
			ADVERTISE_ALL | ADVERTISE_CSMA | ADVERTISE_PAUSE_CAP);
		break;
	}
	default:
		break;
	}

	ax772b_data->Event = AX_NOP;

	return;
}

static int ax88178_set_media(struct usbnet *dev)
{
	int	ret;
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;
	struct ax88178_data *ax178dataptr = data->priv.ax178dataptr;
	int media;

	if ((ret = ax8817x_write_cmd(dev, AX_CMD_SET_SW_MII, 
			0x0000, 0, 0, NULL)) < 0) {
		dbg("enable PHY reg. access capability: %d", ret);
		return ret;				//enable Phy register access capability
	}

	media = ax88178_media_check (dev, ax178dataptr);
	if (media < 0)
		return media;

	if ((ret = ax8817x_write_cmd(dev, AX_CMD_WRITE_MEDIUM_MODE, 
			media, 0, 0, NULL)) < 0) {
		dbg("write mode medium reg failed: %d", ret);
		return ret;
	}

	if ((ret = ax8817x_write_cmd(dev, AX_CMD_SET_HW_MII, 
			0, 0, 0, NULL)) < 0) {
		dbg("disable PHY access failed: %d", ret);
		return ret;
	}

	return 0;
}

static int ax88178_link_reset(struct usbnet *dev)
{
	return ax88178_set_media (dev);
}

static int ax_suspend (struct usb_interface *intf, pm_message_t message)
{
	struct usbnet *dev = usb_get_intfdata(intf);
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;

	return data->suspend (intf, message);
}

static int ax_resume (struct usb_interface *intf)
{
	struct usbnet *dev = usb_get_intfdata(intf);
	struct ax8817x_data *data = (struct ax8817x_data *)&dev->data;

	return data->resume (intf);
}

static const struct driver_info ax88178_info = {
	.description = "ASIX AX88178 USB 2.0 Ethernet",
	.bind = ax88178_bind,
	.status = ax88178_status,
	.link_reset = ax88178_link_reset,
	.reset = ax88178_link_reset,
	.flags =  FLAG_ETHER|FLAG_FRAMING_AX,
	.rx_fixup =	ax88772_rx_fixup,
	.tx_fixup =	ax88772_tx_fixup,
	.data = 0x00130103,  //useless here
};

static const struct driver_info belkin178_info = {
	.description = "Belkin Gigabit USB 2.0 Network Adapter",
	.bind = ax88178_bind,
	.status = ax8817x_status,
	.link_reset = ax88178_link_reset,
	.reset = ax88178_link_reset,
	.flags =  FLAG_ETHER|FLAG_FRAMING_AX,
	.rx_fixup =	ax88772_rx_fixup,
	.tx_fixup =	ax88772_tx_fixup,
	.data = 0x00130103,  //useless here
};

static const struct driver_info ax8817x_info = {
	.description = "ASIX AX8817x USB 2.0 Ethernet",
	.bind = ax8817x_bind,
	.status = ax8817x_status,
	.link_reset = ax88172_link_reset,
	.reset = ax88172_link_reset,
	.flags =  FLAG_ETHER,
	.data = 0x00130103,
};

static const struct driver_info dlink_dub_e100_info = {
	.description = "DLink DUB-E100 USB Ethernet",
	.bind = ax8817x_bind,
	.status = ax8817x_status,
	.link_reset = ax88172_link_reset,
	.reset = ax88172_link_reset,
	.flags =  FLAG_ETHER,
	.data = 0x009f9d9f,
};

static const struct driver_info netgear_fa120_info = {
	.description = "Netgear FA-120 USB Ethernet",
	.bind = ax8817x_bind,
	.status = ax8817x_status,
	.link_reset = ax88172_link_reset,
	.reset = ax88172_link_reset,
	.flags =  FLAG_ETHER,
	.data = 0x00130103,
};

static const struct driver_info hawking_uf200_info = {
	.description = "Hawking UF200 USB Ethernet",
	.bind = ax8817x_bind,
	.status = ax8817x_status,
	.link_reset = ax88172_link_reset,
	.reset = ax88172_link_reset,
	.flags =  FLAG_ETHER,
	.data = 0x001f1d1f,
};

static const struct driver_info ax88772_info = {
	.description = "ASIX AX88772 USB 2.0 Ethernet",
	.bind = ax88772_bind,
	.unbind = ax88772_unbind,
	.status = ax88772_status,
	.flags = FLAG_ETHER | FLAG_FRAMING_AX,
	.rx_fixup = ax88772_rx_fixup,
	.tx_fixup = ax88772_tx_fixup,
	.data = 0x00130103,
};

static const struct driver_info dlink_dub_e100b_info = {
	.description = "D-Link DUB-E100 USB 2.0 Fast Ethernet Adapter",
	.bind = ax88772_bind,
	.unbind = ax88772_unbind,
	.status = ax88772_status,
	.flags = FLAG_ETHER | FLAG_FRAMING_AX,
	.rx_fixup = ax88772_rx_fixup,
	.tx_fixup = ax88772_tx_fixup,
	.data = 0x00130103,
};

static const struct driver_info ax88772a_info = {
	.description = "ASIX AX88772A USB 2.0 Ethernet",
	.bind = ax88772a_bind,
	.unbind = ax88772a_unbind,
	.status = ax88772a_status,
	.flags = FLAG_ETHER | FLAG_FRAMING_AX,
	.rx_fixup = ax88772_rx_fixup,
	.tx_fixup = ax88772_tx_fixup,
//	.data = 0x00130103,
};

static const struct driver_info ax88772b_info = {
	.description = "ASIX AX88772B USB 2.0 Ethernet",
	.bind = ax88772b_bind,
	.unbind = ax88772b_unbind,
	.status = ax88772b_status,
	.flags = FLAG_ETHER | FLAG_FRAMING_AX,
	.rx_fixup = ax88772b_rx_fixup,
	.tx_fixup = ax88772b_tx_fixup,
//	.data = 0x00130103,
};

static const struct usb_device_id	products [] = {
{
	// 88178
	USB_DEVICE (0x0b95, 0x1780),
	.driver_info =	(unsigned long) &ax88178_info,
}, {
	// 88178 for billianton linksys
	USB_DEVICE (0x077b, 0x2226),
	.driver_info =	(unsigned long) &ax88178_info,
}, {
	// ABOCOM for linksys
	USB_DEVICE (0x1737, 0x0039),
	.driver_info =	(unsigned long) &ax88178_info,
}, {
	// ABOCOM  for pci
	USB_DEVICE (0x14ea, 0xab11),
	.driver_info =	(unsigned long) &ax88178_info,
}, {
	// Belkin
	USB_DEVICE (0x050d, 0x5055),
	.driver_info =	(unsigned long) &belkin178_info,
}, {
	// Linksys USB200M
	USB_DEVICE (0x077b, 0x2226),
	.driver_info =	(unsigned long) &ax8817x_info,
}, {
	// Netgear FA120
	USB_DEVICE (0x0846, 0x1040),
	.driver_info =  (unsigned long) &netgear_fa120_info,
}, {
	// DLink DUB-E100
	USB_DEVICE (0x2001, 0x1a00),
	.driver_info =  (unsigned long) &dlink_dub_e100_info,
}, {
	// DLink DUB-E100B
	USB_DEVICE (0x2001, 0x3c05),
	.driver_info =  (unsigned long) &dlink_dub_e100b_info,
}, {
	// DLink DUB-E100B
	USB_DEVICE (0x07d1, 0x3c05),
	.driver_info =  (unsigned long) &dlink_dub_e100b_info,
}, {
	// Intellinet, ST Lab USB Ethernet
	USB_DEVICE (0x0b95, 0x1720),
	.driver_info =  (unsigned long) &ax8817x_info,
}, {
	// Hawking UF200, TrendNet TU2-ET100
	USB_DEVICE (0x07b8, 0x420a),
	.driver_info =  (unsigned long) &hawking_uf200_info,
}, {
        // Billionton Systems, USB2AR
        USB_DEVICE (0x08dd, 0x90ff),
        .driver_info =  (unsigned long) &ax8817x_info,
}, {
	// ATEN UC210T
	USB_DEVICE (0x0557, 0x2009),
	.driver_info =  (unsigned long) &ax8817x_info,
}, {
	// Buffalo LUA-U2-KTX
	USB_DEVICE (0x0411, 0x003d),
	.driver_info =  (unsigned long) &ax8817x_info,
}, {
	// Sitecom LN-029 "USB 2.0 10/100 Ethernet adapter"
	USB_DEVICE (0x6189, 0x182d),
	.driver_info =  (unsigned long) &ax8817x_info,
}, {
	// corega FEther USB2-TX
	USB_DEVICE (0x07aa, 0x0017),
	.driver_info =  (unsigned long) &ax8817x_info,
}, {
	// Surecom EP-1427X-2
	USB_DEVICE (0x1189, 0x0893),
	.driver_info = (unsigned long) &ax8817x_info,
}, {
	// goodway corp usb gwusb2e
	USB_DEVICE (0x1631, 0x6200),
	.driver_info = (unsigned long) &ax8817x_info,
}, {
	// ASIX AX88772 10/100
        USB_DEVICE (0x0b95, 0x7720),
        .driver_info = (unsigned long) &ax88772_info,
}, {
	// ASIX AX88772A 10/100
        USB_DEVICE (0x0b95, 0x772A),
        .driver_info = (unsigned long) &ax88772a_info,
}, {
	// Linksys 200M
        USB_DEVICE (0x13B1, 0x0018),
        .driver_info = (unsigned long) &ax88772a_info,
}, {
	// ASIX AX88772B 10/100
        USB_DEVICE (0x0b95, 0x772B),
        .driver_info = (unsigned long) &ax88772b_info,
},
	{ },		// END
};
MODULE_DEVICE_TABLE(usb, products);

static struct usb_driver asix_driver = {
//	.owner =	THIS_MODULE,
	.name =	"asix",
	.id_table =	products,
	.probe =	usbnet_probe,
	.suspend =	ax_suspend,
	.resume =	ax_resume,
	.disconnect =	usbnet_disconnect,
};

static int __init asix_init(void)
{
 	return usb_register(&asix_driver);
}
module_init(asix_init);

static void __exit asix_exit(void)
{
 	usb_deregister(&asix_driver);
}
module_exit(asix_exit);

MODULE_AUTHOR("David Hollis");
MODULE_DESCRIPTION("ASIX AX8817X based USB 2.0 Ethernet Devices");
MODULE_LICENSE("GPL");

