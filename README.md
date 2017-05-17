# Amazon Web Services HPC Cluster Toolkit
A Java based application that allows the user to manage a cluster of instances on the Amazon Web Services IaaS.

## Software Prerequisities 
- Linux Unbuntu
- Java Virtual Machine
- Apache Maven

## Build the project

## AWS Cluster Toolkit 

### Configure the environment
In your home directory create a directory '.aws' and create a file named 'credentials' contains:
```
[default]
aws_access_key_id=YOUR AWS ACCESS KEY
aws_secret_access_key=YOUR AWS SECRECT KEY
```

### Options
- '-s'          Number of total instaces (min 2, master and slave)
- '-n'          Name of the cluster
- '-a'          Instamce AMI (for MPI support the toolkit considers to use the [StarCLuster](http://star.mit.edu/cluster/) AMI ami-52a0c53b, that is also the default value)
- '-t'         Instances type (the default value is t2.micro)
- '-k-private' Cluster SSH private key 
- '-k-public'  Cluster SSH  public key

## Create new cluster
Run the aws-cluster-toolkit application:

```
java -jar cluster-toolkit-0.0.1-SNAPSHOT.jar -s 2 -n test -k-private pkey -k-public p.pub
```

### How to generate the SSH keys pair

Run the following command and specify a file name where store the keys:
```ssh-keygen -t rsa```


## Configure the user
Consider that your cluster name is 'test', so your username is 'test'. You have to follow these steps:
- Set the password
```sudo passwd test```
- Login as local user
```sudo login test```

## Test MPI Program
- Create a new MPI program
```vim hello.c```
- HelloWorld MPI program
```
#include <mpi.h>
#include <stdio.h>

int main(int argc, char** argv) {
    // Initialize the MPI environment
    MPI_Init(NULL, NULL);

    // Get the number of processes
    int world_size;
    MPI_Comm_size(MPI_COMM_WORLD, &world_size);

    // Get the rank of the process
    int world_rank;
    MPI_Comm_rank(MPI_COMM_WORLD, &world_rank);

    // Get the name of the processor
    char processor_name[MPI_MAX_PROCESSOR_NAME];
    int name_len;
    MPI_Get_processor_name(processor_name, &name_len);

    // Print off a hello world message
    printf("Hello world from processor %s, rank %d"
           " out of %d processors\n",
           processor_name, world_rank, world_size);

    // Finalize the MPI environment.
    MPI_Finalize();
}
```
- Compile the MPI program 
```mpicc hello.c -o hello```
- Copy on all cluster machine the compiled program
```scp hello IP_SLAVE```
- Run the program on the cluster
```mpirun -np 4 --host MASTER,IP_SLAVE1,IP_SLAVE2 hello```
