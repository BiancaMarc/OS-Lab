/*
 * crypto-chrdev.c
 *
 * Implementation of character devices
 * for virtio-cryptodev device 
 *
 * Vangelis Koukis <vkoukis@cslab.ece.ntua.gr>
 * Dimitris Siakavaras <jimsiak@cslab.ece.ntua.gr>
 * Stefanos Gerangelos <sgerag@cslab.ece.ntua.gr>
 *
 */
#include <linux/cdev.h>
#include <linux/poll.h>
#include <linux/sched.h>
#include <linux/module.h>
#include <linux/wait.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>

#include "crypto.h"
#include "crypto-chrdev.h"
#include "debug.h"

#include "cryptodev.h"

/*
 * Global data
 */
struct cdev crypto_chrdev_cdev;

/**
 * Given the minor number of the inode return the crypto device 
 * that owns that number.
 **/
static struct crypto_device *get_crypto_dev_by_minor(unsigned int minor)
{
	struct crypto_device *crdev;
	unsigned long flags;

	debug("Entering");

	spin_lock_irqsave(&crdrvdata.lock, flags);
	list_for_each_entry(crdev, &crdrvdata.devs, list) {
		if (crdev->minor == minor)
			goto out;
	}
	crdev = NULL;

out:
	spin_unlock_irqrestore(&crdrvdata.lock, flags);

	debug("Leaving");
	return crdev;
}

/*************************************
 * Implementation of file operations
 * for the Crypto character device
 *************************************/

static int crypto_chrdev_open(struct inode *inode, struct file *filp)
{
	int ret = 0;
	int err;
	unsigned int len;
	struct crypto_open_file *crof;
	struct crypto_device *crdev;
	unsigned int *syscall_type;
	//int host_fd;

	struct scatterlist syscall_type_sg, host_fd_sg, *sgs[2];
	unsigned int num_out, num_in;

	num_out = 0;
	num_in = 0;	
	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_OPEN;
	//host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	//host_fd = -10;

	ret = -ENODEV;
	if ((ret = nonseekable_open(inode, filp)) < 0)
		goto fail;

	/* Associate this open file with the relevant crypto device. */
	crdev = get_crypto_dev_by_minor(iminor(inode));
	if (!crdev) {
		debug("Could not find crypto device with %u minor", 
				iminor(inode));
		ret = -ENODEV;
		goto fail;
	}

	crof = kzalloc(sizeof(*crof), GFP_KERNEL);
	if (!crof) {
		ret = -ENOMEM;
		goto fail;
	}
	crof->crdev = crdev;
	crof->host_fd = -1;
	filp->private_data = crof;

	/**
	 * We need two sg lists, one for syscall_type and one to get the 
	 * file descriptor from the host.
	 **/
	/* ?? */
	//initializing sg lists
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;

	sg_init_one(&host_fd_sg, &crof->host_fd, sizeof(crof->host_fd));
	sgs[num_out + num_in++] = &host_fd_sg;
	
	down(&crdev->lock);
	//adding virtqueue
	err = virtqueue_add_sgs(crdev->vq, sgs, num_out/*readable*/, num_in/*writable*/, &syscall_type_sg, GFP_ATOMIC); //we don't want to sleep
	if(err<0){
		debug("Didn't add to Virtqueue\n");
		ret = err;
		goto fail;
	}

	//kicking to host
	virtqueue_kick(crdev->vq);

	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	while(virtqueue_get_buf(crdev->vq, &len) == NULL) //returns null if there are no used buffers
		; /*do nothing*/
	up(&crdev->lock);
	/* If host failed to open() return -ENODEV. */
	/* ?? */
	//crof->host_fd=host_fd;
	debug("Host fd is %d\n", crof->host_fd);

	if(crof->host_fd<=0){
		debug("Failed to open\n");
		ret= -ENODEV;
	}	

fail:
	kfree(syscall_type);
	debug("Leaving");
	return ret;
}

static int crypto_chrdev_release(struct inode *inode, struct file *filp)
{
	int ret = 0, err;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	unsigned int *syscall_type;

	struct scatterlist syscall_type_sg, host_fd_sg, *sgs[2];
	unsigned int num_out, len;

	debug("Entering");

	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_CLOSE;
	/**
	 * Send data to the host.
	 **/
	/* ?? */
	num_out=0;

	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;

	sg_init_one(&host_fd_sg, &crof->host_fd, sizeof(crof->host_fd));
	sgs[num_out++] = &host_fd_sg;

	down(&crdev->lock);
	err = virtqueue_add_sgs(crdev->vq, sgs, num_out/*readable*/, 0 /*nothing to write*/, &syscall_type_sg, GFP_ATOMIC); //we don't want to sleep
	if(err<0){
		debug("Didn't add to Virtqueue\n");
		ret = err;
	}

	//kicking to host
	virtqueue_kick(crdev->vq);

	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	while(virtqueue_get_buf(crdev->vq, &len) == NULL) //returns null if there are no used buffers
		; //wait

	up(&crdev->lock);
	kfree(crdev);
	kfree(syscall_type);
	kfree(crof);
	debug("Leaving");
	return ret;

}

static long crypto_chrdev_ioctl(struct file *filp, unsigned int cmd, 
		unsigned long arg)
{
	long ret = 0;
	int err;
	int *host_ret_val;
	struct crypto_open_file *crof = filp->private_data;
	struct crypto_device *crdev = crof->crdev;
	struct virtqueue *vq = crdev->vq;
	struct scatterlist syscall_type_sg, output_msg_sg, input_msg_sg, host_fd_sg, cmd_sg, session_sg, key_sg, ses_id_sg, host_ret_val_sg, crypt_sg, src_sg, iv_sg, dst_sg,
			   *sgs[13];
	unsigned int num_out, num_in, len;
#define MSG_LEN 100
	unsigned char *output_msg, *input_msg;
	unsigned int *syscall_type; // *host_fd;

	struct session_op *session;
	unsigned char *key, *src, *iv, *dst, *usr;
	struct crypt_op *crypt;
	uint32_t *ses_id;
	unsigned int *iocmd;

	unsigned long flags;

	debug("Entering");

	/**
	 * Allocate all data that will be sent to the host.
	 **/
	output_msg = kzalloc(MSG_LEN, GFP_KERNEL);
	input_msg = kzalloc(MSG_LEN, GFP_KERNEL);
	syscall_type = kzalloc(sizeof(*syscall_type), GFP_KERNEL);
	*syscall_type = VIRTIO_CRYPTODEV_SYSCALL_IOCTL;
	//host_fd = kzalloc(sizeof(*host_fd), GFP_KERNEL);
	//host_fd = &(crof->host_fd);
	//debug("In ioctl, host fd is now %d\n", *host_fd);
	num_out = 0;
	num_in = 0;
	iocmd = kzalloc(sizeof(*iocmd), GFP_KERNEL);
	*iocmd = cmd;
	host_ret_val = NULL;
	usr = NULL;
	dst = NULL;
	crypt = NULL;
	session = NULL;
	ses_id = NULL;
	src = NULL;
	iv = NULL;
	key = NULL;
	/**
	 *  These are common to all ioctl commands.
	 **/
	sg_init_one(&syscall_type_sg, syscall_type, sizeof(*syscall_type));
	sgs[num_out++] = &syscall_type_sg;
	/* ?? */
	sg_init_one(&host_fd_sg, &crof->host_fd, sizeof(crof->host_fd));
	sgs[num_out++] = &host_fd_sg;

	sg_init_one(&cmd_sg, iocmd, sizeof(*iocmd));
	sgs[num_out++] = &cmd_sg;

	/**
	 *  Add all the cmd specific sg lists.
	 **/
	switch (cmd) {
		case CIOCGSESSION:
			debug("CIOCGSESSION");
			memcpy(output_msg, "Hello HOST from ioctl CIOCGSESSION.", 36);
			input_msg[0] = '\0';
			sg_init_one(&output_msg_sg, output_msg, MSG_LEN);
			sgs[num_out++] = &output_msg_sg;
			session = kzalloc(sizeof(*session), GFP_KERNEL);
			if(copy_from_user(session, (struct session_op *)arg, sizeof(*session))){
				debug("Failed to copy session\n");
				ret = -1;
				goto fail;
			}

			key = kzalloc(session->keylen*sizeof(unsigned char), GFP_KERNEL);
			if(copy_from_user(key, session->key, session->keylen*sizeof(unsigned char))){
				debug("Failed to copy key\n");
				ret = -1;
				goto fail;
			}
			/*sg_init_one(&session_sg, &session, sizeof(session));
			  sgs[num_out++] = &session_sg;*/
			debug("key is %s\n", key);
			sg_init_one(&key_sg, key, sizeof(*key));
			sgs[num_out++] = &key_sg;

			sg_init_one(&input_msg_sg, input_msg, MSG_LEN);
			sgs[num_out + num_in++] = &input_msg_sg;

			sg_init_one(&session_sg, session, sizeof(*session));
			sgs[num_out + num_in++] = &session_sg;
			
			host_ret_val = kzalloc(sizeof(*host_ret_val), GFP_KERNEL);
			sg_init_one(&host_ret_val_sg, host_ret_val, sizeof(*host_ret_val));
			sgs[num_out + num_in++] = &host_ret_val_sg;

			/*sg_init_one(&input_msg_sg, input_msg, MSG_LEN);
			  sgs[num_out + num_in++] = &input_msg_sg;*/

			break;

		case CIOCFSESSION:
			debug("CIOCFSESSION");
			memcpy(output_msg, "Hello HOST from ioctl CIOCFSESSION.", 36);
			input_msg[0] = '\0';
			sg_init_one(&output_msg_sg, output_msg, MSG_LEN);
			sgs[num_out++] = &output_msg_sg;

			ses_id = kzalloc(sizeof(*ses_id), GFP_KERNEL);
			if(copy_from_user(ses_id, (uint32_t*)arg, (sizeof (uint32_t)))){
				debug("Failed to copy session id\n");
				ret=-1;
				goto fail;
			}

			sg_init_one(&ses_id_sg, ses_id, sizeof(*ses_id));
			sgs[num_out++] = &ses_id_sg;

			sg_init_one(&input_msg_sg, input_msg, MSG_LEN);
			sgs[num_out + num_in++] = &input_msg_sg;

			host_ret_val = kzalloc(sizeof(*host_ret_val), GFP_KERNEL);
			sg_init_one(&host_ret_val_sg, host_ret_val, sizeof(*host_ret_val));
			sgs[num_out + num_in++] = &host_ret_val_sg;

			break;

		case CIOCCRYPT:
			debug("CIOCCRYPT");
			memcpy(output_msg, "Hello HOST from ioctl CIOCCRYPT.", 33);
			input_msg[0] = '\0';
			sg_init_one(&output_msg_sg, output_msg, MSG_LEN);
			sgs[num_out++] = &output_msg_sg;

			crypt = kzalloc(sizeof(*crypt), GFP_KERNEL);
			if(copy_from_user(crypt, (struct crypt_op *)arg, sizeof(*crypt))){
				debug("Failed to copy crypt from user\n");
				ret = 1;
				goto fail;
			}
			sg_init_one(&crypt_sg, crypt, sizeof(*crypt));
			sgs[num_out++] = &crypt_sg;

			src = kzalloc(crypt->len*sizeof(char), GFP_KERNEL);
			if(copy_from_user(src, crypt->src, crypt->len*sizeof(char))){
				debug("Failed to copy source\n");
				ret = 1;
				goto fail;
			}
			sg_init_one(&src_sg, src, crypt->len*sizeof(char));
			sgs[num_out++] = &src_sg;

			iv = kzalloc(sizeof(__u8), GFP_KERNEL);
			if(copy_from_user(iv, crypt->iv, sizeof(__u8))){
				debug("Failed to copy source\n");
				ret = 1;
				goto fail;
			}
			sg_init_one(&iv_sg, iv, sizeof(__u8));
			sgs[num_out++] = &iv_sg;

			sg_init_one(&input_msg_sg, input_msg, MSG_LEN);
			sgs[num_out + num_in++] = &input_msg_sg;

			host_ret_val = kzalloc(sizeof(*host_ret_val), GFP_KERNEL);
                        sg_init_one(&host_ret_val_sg, host_ret_val, sizeof(*host_ret_val));
                        sgs[num_out + num_in++] = &host_ret_val_sg;

			//usr = kzalloc(sizeof(__u8), GFP_KERNEL);
			usr = crypt->dst;
			dst = kzalloc(crypt->len*sizeof(char), GFP_KERNEL);
			/*if(copy_from_user(dst, crypt.dst, crypt.len*sizeof(char))){
				debug("Failed to copy source\n");
				ret = 1;
				goto fail;
			}*/
			sg_init_one(&dst_sg, dst, crypt->len*sizeof(char));
			sgs[num_out + num_in++] = &dst_sg;

			/*sg_init_one(&host_ret_val_sg, &host_ret_val, sizeof(host_ret_val));
			sgs[num_out + num_in++] = &host_ret_val_sg;*/

			break;

		default:
			debug("Unsupported ioctl command");

			break;
	}


	/**
	 * Wait for the host to process our data.
	 **/
	/* ?? */
	/* ?? Lock ?? */

	down(&crdev->lock);

	err = virtqueue_add_sgs(vq, sgs, num_out, num_in,
			&syscall_type_sg, GFP_ATOMIC);
	virtqueue_kick(vq);
	while (virtqueue_get_buf(vq, &len) == NULL)
		/* do nothing */;

	up(&crdev->lock);

	switch (cmd) {
		case CIOCGSESSION:
			debug("CIOGSESSION return");

			if(copy_to_user((struct session_op *)arg, session, sizeof(struct session_op))){
				debug("Failed to copy session id to user\n");
				ret = -1;
				goto fail;
			}
			kfree(key);
			kfree(session);
			break;

		case CIOCFSESSION:
			debug("CIOCFSESSION return");
			kfree(ses_id);
			break;

		case CIOCCRYPT:
			debug("CIOCCRYPT return");
			if(copy_to_user(usr, dst, crypt->len*sizeof(char))){
				debug("Failed to copy dst to user\n");
				ret = -1;
				goto fail;
			}
			kfree(crypt);
			kfree(src);
			kfree(iv);
			break;

	}
	ret = *host_ret_val;

	debug("We said: '%s'", output_msg);
	debug("Host answered: '%s'", input_msg);
	
	kfree(iocmd);
	kfree(host_ret_val);
	kfree(output_msg);
	kfree(input_msg);
	kfree(syscall_type);

fail:
	debug("Leaving");
	return ret;
}

static ssize_t crypto_chrdev_read(struct file *filp, char __user *usrbuf, 
		size_t cnt, loff_t *f_pos)
{
	debug("Entering");
	debug("Leaving");
	return -EINVAL;
}

static struct file_operations crypto_chrdev_fops = 
{
	.owner          = THIS_MODULE,
	.open           = crypto_chrdev_open,
	.release        = crypto_chrdev_release,
	.read           = crypto_chrdev_read,
	.unlocked_ioctl = crypto_chrdev_ioctl,
};

int crypto_chrdev_init(void)
{
	int ret;
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("Initializing character device...");
	cdev_init(&crypto_chrdev_cdev, &crypto_chrdev_fops);
	crypto_chrdev_cdev.owner = THIS_MODULE;

	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	ret = register_chrdev_region(dev_no, crypto_minor_cnt, "crypto_devs");
	if (ret < 0) {
		debug("failed to register region, ret = %d", ret);
		goto out;
	}
	ret = cdev_add(&crypto_chrdev_cdev, dev_no, crypto_minor_cnt);
	if (ret < 0) {
		debug("failed to add character device");
		goto out_with_chrdev_region;
	}

	debug("Completed successfully");
	return 0;

out_with_chrdev_region:
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
out:
	return ret;
}

void crypto_chrdev_destroy(void)
{
	dev_t dev_no;
	unsigned int crypto_minor_cnt = CRYPTO_NR_DEVICES;

	debug("entering");
	dev_no = MKDEV(CRYPTO_CHRDEV_MAJOR, 0);
	cdev_del(&crypto_chrdev_cdev);
	unregister_chrdev_region(dev_no, crypto_minor_cnt);
	debug("leaving");
}
