package main

import (
	"fmt"
	"os"

	ec2_classic "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/ec2"
	"github.com/pulumi/pulumi-awsx/sdk/go/awsx/ec2"
	"github.com/pulumi/pulumi-tls/sdk/v4/go/tls"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

const RKE2_AMI_ID = "ami-0bb262a4b5d64ce94"
const DEFAULT_USER = "ubuntu"

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		vpc, err := ec2.NewVpc(ctx, "dashdays-oursler", nil)

		if err != nil {
			return err
		}

		// Tokesn and keys to pass to the instances.
		rke2JoinToken := "asdfasdfasdfasdfasdfasdfasdf" // hardcoded for now for POC

		privateKey, keyPair, _ := createKey(ctx)

		privateKey.PrivateKeyPem.ApplyT(func(pem string) error {
			f, _ := os.Create("private.pem")
			defer f.Close()

			_, err := f.WriteString(pem)

			return err
		})

		// Security Group for the instances to allow RKE2 and SSH.
		securityGroup, err := ec2_classic.NewSecurityGroup(ctx, "dashdays-sg", &ec2_classic.SecurityGroupArgs{
			Description: pulumi.String("Allow demo traffic"),
			VpcId:       vpc.VpcId,
			Tags: pulumi.StringMap{
				"Name": pulumi.String("dash-days-sg"),
			},
			Ingress: ec2_classic.SecurityGroupIngressArray{
				ec2_classic.SecurityGroupIngressArgs{
					FromPort: pulumi.Int(22),
					ToPort:   pulumi.Int(22),
					Protocol: pulumi.String("tcp"),
					CidrBlocks: pulumi.StringArray{
						pulumi.String("0.0.0.0/0"),
					},
				},
				ec2_classic.SecurityGroupIngressArgs{
					FromPort: pulumi.Int(6443),
					ToPort:   pulumi.Int(6443),
					Protocol: pulumi.String("tcp"),
					CidrBlocks: pulumi.StringArray{
						pulumi.String("0.0.0.0/0"),
					},
				},
				ec2_classic.SecurityGroupIngressArgs{
					FromPort: pulumi.Int(9345),
					ToPort:   pulumi.Int(9345),
					Protocol: pulumi.String("tcp"),
					CidrBlocks: pulumi.StringArray{
						pulumi.String("0.0.0.0/0"),
					},
				},
				ec2_classic.SecurityGroupIngressArgs{ // Just get this working for now.
					FromPort: pulumi.Int(0),
					ToPort:   pulumi.Int(65535),
					Protocol: pulumi.String("tcp"),
					CidrBlocks: pulumi.StringArray{
						pulumi.String("0.0.0.0/0"),
					},
				},
			},
			Egress: ec2_classic.SecurityGroupEgressArray{
				ec2_classic.SecurityGroupEgressArgs{
					FromPort: pulumi.Int(0),
					ToPort:   pulumi.Int(65535),
					Protocol: pulumi.String("tcp"),
					CidrBlocks: pulumi.StringArray{
						pulumi.String("0.0.0.0/0"),
					},
				},
			},
		})
		if err != nil {
			return err
		}

		// Once the VPC subnets are available, we can deploy RKE2 instances into the public subnet for the demo.
		vpc.PublicSubnetIds.ApplyT(func(ids []string) error {
			// Bootstrap node
			bootstrapNode, err := ec2_classic.NewInstance(ctx, "test_bootstrap_node", &ec2_classic.InstanceArgs{
				Ami:                     pulumi.String(RKE2_AMI_ID),
				InstanceType:            pulumi.String("c5.xlarge"),
				UserDataReplaceOnChange: pulumi.Bool(true),
				UserData:                pulumi.String(getUserData("", "false", rke2JoinToken, DEFAULT_USER, "cluster.foo.bar")),
				SubnetId:                pulumi.String(ids[0]),
				KeyName:                 keyPair.KeyName,
				VpcSecurityGroupIds:     pulumi.StringArray{securityGroup.ID()},
				RootBlockDevice: ec2_classic.InstanceRootBlockDeviceArgs{
					VolumeSize: pulumi.Int(100),
				},
				Tags: pulumi.StringMap{
					"Name": pulumi.String("dash-days-bootstrap-node"),
				},
			})
			if err != nil {
				return err
			}

			// Once the bootstrap node's IP is available, we can deploy the other nodes.
			bootstrapNode.PrivateIp.ApplyT(func(ip string) error {
				// Generate some control plane nodes
				numCpNodes := 2
				for i := 0; i < numCpNodes; i++ {
					_, err = ec2_classic.NewInstance(ctx, fmt.Sprintf("control_plane_node-%d", i+1), &ec2_classic.InstanceArgs{
						Ami:                     pulumi.String(RKE2_AMI_ID),
						InstanceType:            pulumi.String("c5.xlarge"),
						UserDataReplaceOnChange: pulumi.Bool(true),
						UserData:                pulumi.String(getUserData(ip, "false", rke2JoinToken, DEFAULT_USER, "cluster.foo.bar")),
						SubnetId:                pulumi.String(ids[0]),
						KeyName:                 keyPair.KeyName,
						VpcSecurityGroupIds:     pulumi.StringArray{securityGroup.ID()},
						RootBlockDevice: ec2_classic.InstanceRootBlockDeviceArgs{
							VolumeSize: pulumi.Int(100),
						},
						Tags: pulumi.StringMap{
							"Name": pulumi.String(fmt.Sprintf("dash-days-control-plane-node-%d", i+1)),
						},
					})
					if err != nil {
						return err
					}
				}

				// Agent node
				numAgentNodes := 3
				for i := 0; i < numAgentNodes; i++ {
					_, err = ec2_classic.NewInstance(ctx, fmt.Sprintf("test_agent_node-%d", i+1), &ec2_classic.InstanceArgs{
						Ami:                     pulumi.String(RKE2_AMI_ID),
						InstanceType:            pulumi.String("c5.xlarge"),
						UserDataReplaceOnChange: pulumi.Bool(true),
						UserData:                pulumi.String(getUserData(ip, "true", rke2JoinToken, DEFAULT_USER, "cluster.foo.bar")),
						SubnetId:                pulumi.String(ids[0]),
						KeyName:                 keyPair.KeyName,
						VpcSecurityGroupIds:     pulumi.StringArray{securityGroup.ID()},
						RootBlockDevice: ec2_classic.InstanceRootBlockDeviceArgs{
							VolumeSize: pulumi.Int(100),
						},
						Tags: pulumi.StringMap{
							"Name": pulumi.String(fmt.Sprintf("dash-days-agent-node-%d", i+1)),
						},
					})
				}
				return err
			})
			return err
		})
		if err != nil {
			return err
		}

		ctx.Export("vpcId", vpc.VpcId)
		ctx.Export("privateSubnetIds", vpc.PrivateSubnetIds)
		ctx.Export("publicSubnetIds", vpc.PublicSubnetIds)
		ctx.Export("privateKey", privateKey.PrivateKeyPem)
		return nil
	})
}

func getUserData(bootstrapIp string, agentNode string, rke2JoinToken string, defaultUser string, clusterSans string) string {
	return fmt.Sprintf(`#!/bin/bash
echo "Please work."

# If no bootstrap IP is provided then start RKE2 as single node/bootstrap
if [[ "%s" == "" ]]; then
    bootstrap_ip=$(ip route get $(ip route show 0.0.0.0/0 | grep -oP 'via \K\S+') | grep -oP 'src \K\S+')
else
    bootstrap_ip=%s
fi

if [[ "%s" ]]; then
    echo "Passing SANs to RKE2 startup script: %s"
    san_options="-T %s"
fi

echo "Bootstrap node IP: ${bootstrap_ip}"

if [[ "%s" == "true" ]]; then
    /root/rke2-startup.sh -t %s ${san_options} -s ${bootstrap_ip} -u %s -a
else
    /root/rke2-startup.sh -t %s ${san_options} -s ${bootstrap_ip} -u %s
fi
`, bootstrapIp, bootstrapIp, clusterSans, clusterSans, clusterSans, agentNode, rke2JoinToken, defaultUser, rke2JoinToken, defaultUser)
}

func createKey(ctx *pulumi.Context) (*tls.PrivateKey, *ec2_classic.KeyPair, error) {
	pk, err := tls.NewPrivateKey(
		ctx,
		"dashdays-privatekey",
		&tls.PrivateKeyArgs{
			Algorithm: pulumi.String("RSA"),
			RsaBits:   pulumi.Int(4096),
		})
	if err != nil {
		return nil, nil, err
	}
	kp, err := ec2_classic.NewKeyPair(ctx,
		"dashdays-keypair",
		&ec2_classic.KeyPairArgs{
			PublicKey: pk.PublicKeyOpenssh,
		})
	if err != nil {
		return nil, nil, err
	}
	return pk, kp, nil
}
