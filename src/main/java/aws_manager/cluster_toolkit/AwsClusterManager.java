package aws_manager.cluster_toolkit;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.kohsuke.args4j.CmdLineParser;
import org.kohsuke.args4j.Option;

import com.amazonaws.AmazonServiceException;
import com.amazonaws.auth.profile.ProfileCredentialsProvider;
import com.amazonaws.services.ec2.AmazonEC2;
import com.amazonaws.services.ec2.AmazonEC2ClientBuilder;
import com.amazonaws.services.ec2.model.AuthorizeSecurityGroupIngressRequest;
import com.amazonaws.services.ec2.model.CreateKeyPairRequest;
import com.amazonaws.services.ec2.model.CreateKeyPairResult;
import com.amazonaws.services.ec2.model.CreateSecurityGroupRequest;
import com.amazonaws.services.ec2.model.CreateSecurityGroupResult;
import com.amazonaws.services.ec2.model.CreateTagsRequest;
import com.amazonaws.services.ec2.model.DescribeAvailabilityZonesResult;
import com.amazonaws.services.ec2.model.DescribeInstancesResult;
import com.amazonaws.services.ec2.model.DescribeKeyPairsResult;
import com.amazonaws.services.ec2.model.Instance;
import com.amazonaws.services.ec2.model.InstanceStateName;
import com.amazonaws.services.ec2.model.IpPermission;
import com.amazonaws.services.ec2.model.IpRange;
import com.amazonaws.services.ec2.model.KeyPairInfo;
import com.amazonaws.services.ec2.model.Reservation;
import com.amazonaws.services.ec2.model.RunInstancesRequest;
import com.amazonaws.services.ec2.model.RunInstancesResult;
import com.amazonaws.services.ec2.model.Tag;
import com.jcraft.jsch.ChannelExec;
import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;
import com.jcraft.jsch.SftpException;

public class AwsClusterManager {

	/*
	 * Before running the code:
	 *      Fill in your AWS access credentials in the provided credentials
	 *      file template, and be sure to move the file to the default location
	 *      (~/.aws/credentials) where the sample code will load the
	 *      credentials from.
	 *      https://console.aws.amazon.com/iam/home?#security_credential
	 *
	 * WARNING:
	 *      To avoid accidental leakage of your credentials, DO NOT keep
	 *      the credentials file in your source directory.
	 */

	static AmazonEC2  ec2;

	static String MY_KEY = "cluster-red-key";
	private static void init() throws Exception {

		ec2 = AmazonEC2ClientBuilder.standard().withRegion("us-east-1").withCredentials(new ProfileCredentialsProvider()).build();
	}

	@Option(name="-s",usage="number of total instaces (min 2, master and slave)")
	private int size=2;
	@Option(name="-n",usage="name of the cluster")
	private String name;
	@Option(name="-a",usage="instamce AMI")
	private String ami="ami-52a0c53b"; //ami-80861296 Ubuntu Server 16.04 LTS HVM, SSD Volume Type -- ami-52a0c53b StarCluster
	@Option(name="-t",usage="instances type")
	private String type="t2.micro";
	@Option(name="-k-private",usage="Cluster /usr/bin/ssh key private")
	private String prk;
	@Option(name="-k-public",usage="Cluster /usr/bin/ssh key public")
	private String puk;


	public static void main(String[] args) throws Exception {
		new AwsClusterManager().doMain(args);
	}
	public void doMain(String[] args) throws Exception{

		CmdLineParser parser = new CmdLineParser(this);
		parser.parseArgument(args);
		System.out.println("=============================================================");
		System.out.println("Welcome to the AWS Cluster Toolkit by Carmine Spagnuolo v.0.1");
		System.out.println("=============================================================");

		init();

		try {
			DescribeAvailabilityZonesResult availabilityZonesResult = ec2.describeAvailabilityZones();
			System.out.println("You have access to " + availabilityZonesResult.getAvailabilityZones().size() +
					" Availability Zones.");

			DescribeInstancesResult describeInstancesRequest = ec2.describeInstances();
			List<Reservation> reservations = describeInstancesRequest.getReservations();
			Set<Instance> instances = new HashSet<Instance>();

			for (Reservation reservation : reservations) {
				instances.addAll(reservation.getInstances());
			}

			System.out.println("You have " + instances.size() + " Amazon EC2 instance(s).");

			if(size == 0){
				System.out.println("The number of instances should be greater than 2!");
				System.exit(0);
			}
			System.out.println("Start a cluster with name "+name+" of "+size+" instaces!");

			//CREATE SECURITY GROUP FOR CLUSTER WITH /usr/bin/ssh
			String GROUP_NAME=name+""+(new Long(System.currentTimeMillis()).hashCode());
			createSecurityGroupByClusterName(GROUP_NAME);

			//CREATE /usr/bin/ssh ACCESS
			createKeyPair();

			//RUN MASTER NODE
			RunInstancesResult masterresult = 
					runInstance(GROUP_NAME,"Master");
			//RUN SLAVE NODES
			ArrayList<RunInstancesResult> slaves_results=new ArrayList<RunInstancesResult>();
			for (int i = 0; i < size-1; i++) {
				slaves_results.add(runInstance(GROUP_NAME,"Slave"+i));
			}
			String masterID=masterresult.getReservation().getInstances().get(0).getInstanceId();

			String hosts=masterresult.getReservation().getInstances().get(0).getPrivateIpAddress();
			for (int i = 0; i < slaves_results.size(); i++)
			{
				hosts+=","+slaves_results.get(i).getReservation().getInstances().get(0).getPrivateIpAddress();
			}
			System.out.print("Internal hosts List: ");
			System.out.println(hosts);

			//WAIT MASTER NODE
			System.out.println("Waiting to cluster running ..");
			String MASTER_DNS=null;
			boolean isRunning=false;
			do {
				describeInstancesRequest = ec2.describeInstances();
				reservations = describeInstancesRequest.getReservations();
				for (Reservation reservation : reservations) {
					if(reservation.getInstances().get(0).getInstanceId().equalsIgnoreCase(masterID))
					{
						if(reservation.getInstances().get(0).getPublicDnsName()!=null && !reservation.getInstances().get(0).getPublicDnsName().isEmpty())
						{
							if(reservation.getInstances().get(0).getState().getName().equals(InstanceStateName.Running.toString())){
								MASTER_DNS=reservation.getInstances().get(0).getPublicDnsName();
								System.out.println("Master "+MASTER_DNS+" node running..");
								isRunning = true;
							}
						}
					}
				}
				Thread.sleep(500);
			} while (!isRunning);


			//COMPUTE DNS OF SLAVE NODES
			//WAIT SLAVES NODE
			ArrayList<String> slaves_dns=new ArrayList<String>();
			do {
				describeInstancesRequest = ec2.describeInstances();
				reservations = describeInstancesRequest.getReservations();
				for (Reservation reservation : reservations) {
					for (RunInstancesResult rslave : slaves_results) {
						if(reservation.getInstances().get(0).getInstanceId().equalsIgnoreCase(rslave.getReservation().getInstances().get(0).getInstanceId())){
							if(reservation.getInstances().get(0).getPublicDnsName()!=null && !reservation.getInstances().get(0).getPublicDnsName().isEmpty())
							{
								if(reservation.getInstances().get(0).getState().getName().equals(InstanceStateName.Running.toString())){
									System.out.println("Slave "+reservation.getInstances().get(0).getPublicDnsName()+"node running..");
									slaves_dns.add(reservation.getInstances().get(0).getPublicDnsName());
								}
							}
						}
					}

				}
				Thread.sleep(500);
			} while (slaves_dns.size()!=slaves_results.size());

			//Wait connection /usr/bin/ssh this is not good :-( try and try
			boolean master_configured=false;
			do {
				try {
					createClusterUser(MASTER_DNS,name);
					master_configured=true;
				} catch (Exception e) {
					// TODO: handle exception
					Thread.sleep(1000);
					//System.out.println(e.getMessage());
				}
			} while (!master_configured);

			for (String dslave : slaves_dns) {
				boolean slave_configured=false;
				do {
					try {
						createClusterUser(dslave,name);
						slave_configured=true;
					} catch (Exception e) {
						// TODO: handle exception
						Thread.sleep(1000);
						//System.out.println(e.getMessage());
					}
				} while (!slave_configured);

			}
			System.out.println("Done.\n-----------------------------------------------");

			System.out.println("Connect to Master Node:");
			System.out.println("/usr/bin/ssh -i "+System.getProperty("user.home")+"/.aws/"+MY_KEY+".pem"+
					" ubuntu@"+MASTER_DNS);


		} catch (AmazonServiceException ase) {
			System.out.println("Caught Exception: " + ase.getMessage());
			System.out.println("Reponse Status Code: " + ase.getStatusCode());
			System.out.println("Error Code: " + ase.getErrorCode());
			System.out.println("Request ID: " + ase.getRequestId());
		}

	}
	private void createClusterUser(String publicdns, String clustername)
			throws JSchException, SftpException {
		System.out.println("Configuring "+publicdns+" node");
		JSch jsch=new JSch();

		jsch.addIdentity(System.getProperty("user.home")+"/.aws/"+MY_KEY+".pem");
		Session session = jsch.getSession("ubuntu", publicdns, 22);

		session.setConfig("StrictHostKeyChecking", "no");
		session.connect();

		//sudo useradd -s /bin/bash -m -d /home/USERNAME  -g root USERNAME
		ChannelExec euser=(ChannelExec) session.openChannel("exec");
		String username=clustername;
		euser.setCommand("sudo useradd -s /bin/bash -m -d /home/"+username+" -g root "+username);
		euser.setInputStream(null);
		euser.connect();
		euser.disconnect();

		euser=(ChannelExec) session.openChannel("exec");
		euser.setCommand("sudo mkdir -p /home/"+username+"/.ssh");
		euser.setInputStream(null);
		euser.connect();
		euser.disconnect();

		String[] prknames=prk.split("/");
		String[] puknames=puk.split("/");

		//		Channel channel = session.openChannel("sftp");
		//		channel.connect();
		//		ChannelSftp sftpChannel = (ChannelSftp) channel;
		//		sftpChannel.put(prk,".ssh/"+prknames[prknames.length-1]);
		//		System.out.println(prk+" "+"/home/ubuntu/.ssh/"+prknames[prknames.length-1]);
		//		sftpChannel.put(puk,"/home/ubuntu/.ssh/"+puknames[puknames.length-1]);
		//		sftpChannel.disconnect();


		try {
			Process scp1 = Runtime.getRuntime().exec("/usr/bin/scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "+System.getProperty("user.home")+"/.aws/"+MY_KEY+".pem "+
					prk+" ubuntu@"+publicdns+":/home/ubuntu/.ssh/id_rsa");

			Process scp2=Runtime.getRuntime().exec("/usr/bin/scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "+System.getProperty("user.home")+"/.aws/"+MY_KEY+".pem "+
					puk+" ubuntu@"+publicdns+":/home/ubuntu/.ssh/id_rsa.pub");

			scp1.waitFor();
			scp2.waitFor();

			Process cp1 = Runtime.getRuntime().exec("/usr/bin/ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "+System.getProperty("user.home")+"/.aws/"+MY_KEY+".pem "+
					" ubuntu@"+publicdns+" "+"sudo cp /home/ubuntu/.ssh/id_rsa.pub /home/"+username+"/.ssh");
			Process cp2 = Runtime.getRuntime().exec("/usr/bin/ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "+System.getProperty("user.home")+"/.aws/"+MY_KEY+".pem "+
					" ubuntu@"+publicdns+" "+"sudo cp /home/ubuntu/.ssh/id_rsa  /home/"+username+"/.ssh");

			cp1.waitFor();
			cp2.waitFor();

			Process cat1 = Runtime.getRuntime().exec("/usr/bin/ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "+
					System.getProperty("user.home")+"/.aws/"+MY_KEY+".pem "+
					" ubuntu@"+publicdns+" "+
					"sudo /bin/touch /home/"+username+"/.ssh/authorized_keys");cat1.waitFor();
			Process cat6 = Runtime.getRuntime().exec("/usr/bin/ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "+
					System.getProperty("user.home")+"/.aws/"+MY_KEY+".pem "+
					" ubuntu@"+publicdns+" "+
					"sudo /bin/chmod 777 /home/"+username+"/.ssh/authorized_keys");cat6.waitFor();	
			Process cat4 = Runtime.getRuntime().exec("/usr/bin/ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "+
					System.getProperty("user.home")+"/.aws/"+MY_KEY+".pem "+
					" ubuntu@"+publicdns+" "+
					"sudo /bin/cat /home/"+username+"/.ssh/id_rsa.pub >> /home/"+username+"/.ssh/authorized_keys");	cat4.waitFor();
					
			Process cat3 = Runtime.getRuntime().exec("/usr/bin/ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "+
					System.getProperty("user.home")+"/.aws/"+MY_KEY+".pem "+
					" ubuntu@"+publicdns+" "+
					"sudo /bin/chown -R test:root /home/"+username+"/.ssh");cat3.waitFor();
					
			Process cat2 = Runtime.getRuntime().exec("/usr/bin/ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "+
					System.getProperty("user.home")+"/.aws/"+MY_KEY+".pem "+
					" ubuntu@"+publicdns+" "+
					"sudo /bin/chmod 640 /home/"+username+"/.ssh/authorized_keys");cat2.waitFor();
					
			Process cat5 = Runtime.getRuntime().exec("/usr/bin/ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "+
				    System.getProperty("user.home")+"/.aws/"+MY_KEY+".pem "+
					" ubuntu@"+publicdns+" "+
					"sudo /bin/chmod -R 700 /home/"+username+"/.ssh");cat5.waitFor();	
			Process cat7 = Runtime.getRuntime().exec("/usr/bin/ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -i "+
					System.getProperty("user.home")+"/.aws/"+MY_KEY+".pem "+
					" ubuntu@"+publicdns+" "+
					"sudo chown -R test:root /home/"+username+"");cat7.waitFor();	

			
		
			//			cat2.waitFor();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InterruptedException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		//		
		//		euser=(ChannelExec) session.openChannel("exec");
		//		euser.setCommand("sudo cp /home/ubuntu/.ssh/"+prknames[prknames.length-1] +"/home/"+username+"/.ssh");
		//		euser.setInputStream(null);
		//		euser.connect();
		//		euser.disconnect();
		//
		//		euser=(ChannelExec) session.openChannel("exec");
		//		euser.setCommand("sudo cp /home/ubuntu/.ssh/"+puknames[prknames.length-1] +"/home/"+username+"/.ssh");
		//		euser.setInputStream(null);
		//		euser.connect();
		//		euser.disconnect();

		//		channel.disconnect();
		session.disconnect();
	}
	private RunInstancesResult runInstance(String GROUP_NAME, String clustertype) {
		RunInstancesRequest runInstancesRequest = new RunInstancesRequest();

		runInstancesRequest.withImageId(ami)
		.withInstanceType(type)
		.withMinCount(1)
		.withMaxCount(1)
		.withKeyName(MY_KEY)
		.withSecurityGroups(GROUP_NAME);

		RunInstancesResult result = ec2.runInstances(runInstancesRequest);
		System.out.println(clustertype+" node reservation:"+result.getReservation().getInstances().get(0).getInstanceId());

		tagInstance(result.getReservation().getInstances().get(0).getInstanceId(),"Name",name+"-"+clustertype,ec2);

		return result;
	}
	public void tagInstance(String instanceId, String tag, String value, AmazonEC2 ec2Client) {
		System.out.println(instanceId);
		//quick fix
		try {
			Thread.sleep(1000);
		} catch (InterruptedException e) {
			// swallow
		}
		CreateTagsRequest request = new CreateTagsRequest();
		request = request.withResources(instanceId)
				.withTags(new Tag(tag, value));
		ec2Client.createTags(request);
	}
	private void createKeyPair() throws IOException, FileNotFoundException {
		DescribeKeyPairsResult response = ec2.describeKeyPairs();
		boolean check_key=false;
		for(KeyPairInfo key_pair : response.getKeyPairs()) {
			if(key_pair.getKeyName().equalsIgnoreCase(MY_KEY))
			{
				check_key=true;
				break;
			}
		}
		if(!check_key)
		{
			File file=new File(System.getProperty("user.home")+"/.aws/"+MY_KEY+".pem");
			if(!file.exists()) file.createNewFile();
			else{
				System.err.println("Connot create the key pair to access to the cluster!");
				System.exit(1);
			}
			System.out.println("Create new key pair ~/.aws/"+MY_KEY+".pem");
			CreateKeyPairRequest request = new CreateKeyPairRequest()
			.withKeyName(MY_KEY);

			CreateKeyPairResult responsetocreate = ec2.createKeyPair(request);


			PrintWriter print = new PrintWriter(file);
			print.print(responsetocreate.getKeyPair().getKeyMaterial());
			print.close();
			Runtime.getRuntime().exec("chmod 0400 "+System.getProperty("user.home")+"/.aws/"+MY_KEY+".pem");
		}
	}
	private void createSecurityGroupByClusterName(String GROUP_NAME) {
		System.out.println("Creating security group for cluster "+name);
		CreateSecurityGroupRequest csgr = new CreateSecurityGroupRequest();

		csgr.withGroupName(GROUP_NAME).withDescription("AWS Cluster toolkit security group");
		CreateSecurityGroupResult createSecurityGroupResult =ec2.createSecurityGroup(csgr);

		IpPermission ipPermission =
				new IpPermission();

		IpRange ipRange1 = new IpRange().withCidrIp("0.0.0.0/0");


		ipPermission.withIpv4Ranges(Arrays.asList(new IpRange[] {ipRange1}))
		.withIpProtocol("tcp")
		.withFromPort(0)
		.withToPort(65535);
		AuthorizeSecurityGroupIngressRequest authorizeSecurityGroupIngressRequest =
				new AuthorizeSecurityGroupIngressRequest();

		authorizeSecurityGroupIngressRequest.withGroupName(GROUP_NAME)
		.withIpPermissions(ipPermission);
		ec2.authorizeSecurityGroupIngress(authorizeSecurityGroupIngressRequest);
		System.out.println("Created new security group "+GROUP_NAME+" with /usr/bin/ssh enabled.");

	}
}
