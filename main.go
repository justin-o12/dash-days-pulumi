package main

import (
	"crypto/rand"
	"fmt"
  "os"

	ec2_classic "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/ec2"
	//vpc_classic "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/vpc"
	//ec2_native "github.com/pulumi/pulumi-aws-native/sdk/go/aws/ec2"
	//eks_native "github.com/pulumi/pulumi-aws-native/sdk/go/aws/eks"
	//iam_native "github.com/pulumi/pulumi-aws-native/sdk/go/aws/iam"
	//iam_classic "github.com/pulumi/pulumi-aws/sdk/v6/go/aws/iam"
	"github.com/pulumi/pulumi-awsx/sdk/go/awsx/ec2"
	//"github.com/pulumi/pulumi-eks/sdk/go/eks"
	"github.com/pulumi/pulumi-tls/sdk/v4/go/tls"
	"github.com/pulumi/pulumi/sdk/v3/go/pulumi"
)

const RKE2_AMI_ID = "ami-0c1f149fb152ba3b6" //"uds-rke2-ubuntu-202309212052"
const DEFAULT_USER = "ubuntu"

func main() {
	pulumi.Run(func(ctx *pulumi.Context) error {
		vpc, err := ec2.NewVpc(ctx, "dashdays-oursler", nil)

		if err != nil {
			return err
		}

		/*userDataFile, err := ioutil.ReadFile("user_data.sh")
		  if err != nil {
		    return err
		  }*/

		rke2JoinToken := getRandomToken()

		privateKey, keyPair, _ := createKey(ctx)

    privateKey.PrivateKeyPem.ApplyT(func(pem string) error {
       f, _ := os.Create("private.pem")
       defer f.Close()

       _, err := f.WriteString(pem)

       return err
    })

    securityGroup, err := ec2_classic.NewSecurityGroup(ctx, "dashdays-sg", &ec2_classic.SecurityGroupArgs{
      Description: pulumi.String("Allow demo traffic"),
      VpcId:       vpc.VpcId, //pulumi.Any(vpc.VpcId),
      Tags: pulumi.StringMap{
        "Name": pulumi.String("dash-days-sg"),
      },
      Ingress: ec2_classic.SecurityGroupIngressArray{
        ec2_classic.SecurityGroupIngressArgs{
          FromPort: pulumi.Int(22),
          ToPort: pulumi.Int(22),
          Protocol: pulumi.String("tcp"),
          CidrBlocks: pulumi.StringArray{
            pulumi.String("0.0.0.0/0"),
          },
        },
        ec2_classic.SecurityGroupIngressArgs{
          FromPort: pulumi.Int(6443),
          ToPort: pulumi.Int(6443),
          Protocol: pulumi.String("tcp"),
          CidrBlocks: pulumi.StringArray{
            pulumi.String("0.0.0.0/0"),
          },
        },
        ec2_classic.SecurityGroupIngressArgs{
          FromPort: pulumi.Int(9345),
          ToPort: pulumi.Int(9345),
          Protocol: pulumi.String("tcp"),
          CidrBlocks: pulumi.StringArray{
            pulumi.String("0.0.0.0/0"),
          },
        },
      },
      Egress: ec2_classic.SecurityGroupEgressArray{
        ec2_classic.SecurityGroupEgressArgs{
          FromPort: pulumi.Int(0),
          ToPort: pulumi.Int(0),
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

    /*
    _, err = vpc_classic.NewSecurityGroupEgressRule(ctx, "dashdays-sg-egress", &vpc_classic.SecurityGroupEgressRuleArgs{
      SecurityGroupId: securityGroup.ID(),
      CidrIpv4:        pulumi.String("0.0.0.0/0"),
      FromPort:        pulumi.Int(0),
      IpProtocol:      pulumi.String("tcp"),
      ToPort:          pulumi.Int(0),
    })
    if err != nil {
      return err
    }

    _, err = vpc_classic.NewSecurityGroupIngressRule(ctx, "dashdays-sg-ssh-ingress", &vpc_classic.SecurityGroupIngressRuleArgs{
      SecurityGroupId: securityGroup.ID(),
      CidrIpv4:        pulumi.String("0.0.0.0/0"),
      FromPort:        pulumi.Int(22),
      IpProtocol:      pulumi.String("tcp"),
      ToPort:          pulumi.Int(22),
    })
    if err != nil {
      return err
    }
    _, err = vpc_classic.NewSecurityGroupIngressRule(ctx, "dashdays-sg-9345-ingress", &vpc_classic.SecurityGroupIngressRuleArgs{
      SecurityGroupId: securityGroup.ID(),
      CidrIpv4:        pulumi.String("0.0.0.0/0"),
      FromPort:        pulumi.Int(9345),
      IpProtocol:      pulumi.String("tcp"),
      ToPort:          pulumi.Int(9345),
    })
    if err != nil {
      return err
    }
    _, err = vpc_classic.NewSecurityGroupIngressRule(ctx, "dashdays-sg-6443-ingress", &vpc_classic.SecurityGroupIngressRuleArgs{
      SecurityGroupId: securityGroup.ID(),
      CidrIpv4:        pulumi.String("0.0.0.0/0"),
      FromPort:        pulumi.Int(6443),
      IpProtocol:      pulumi.String("tcp"),
      ToPort:          pulumi.Int(6443),
    })
    if err != nil {
      return err
    }
    */

		vpc.PublicSubnetIds.ApplyT(func(ids []string) error {
			bootstrapNode, err := ec2_classic.NewInstance(ctx, "test_bootstrap_node", &ec2_classic.InstanceArgs{
				Ami:          pulumi.String(RKE2_AMI_ID),
				InstanceType: pulumi.String("c5.xlarge"),
				UserData:     pulumi.String(getUserData("", "false", rke2JoinToken, DEFAULT_USER, "cluster.foo.bar")),
				SubnetId:     pulumi.String(ids[0]),
				KeyName:      keyPair.KeyName,
        VpcSecurityGroupIds: pulumi.StringArray{securityGroup.ID()},
        //SecurityGroups: pulumi.StringArray{securityGroup.ID()},
				Tags: pulumi.StringMap{
				  "Name": pulumi.String("dash-days-bootstrap-node"),
				},
			})
			if err != nil {
				return err
			}

			bootstrapNode.PrivateIp.ApplyT(func(ip string) error {
				_, err = ec2_classic.NewInstance(ctx, "control_plane_node", &ec2_classic.InstanceArgs{
					Ami:          pulumi.String(RKE2_AMI_ID),
					InstanceType: pulumi.String("c5.xlarge"),
					UserData:     pulumi.String(getUserData(ip, "false", rke2JoinToken, DEFAULT_USER, "cluster.foo.bar")),
					SubnetId:     pulumi.String(ids[0]),
					KeyName:      keyPair.KeyName,
          VpcSecurityGroupIds: pulumi.StringArray{securityGroup.ID()},
          //SecurityGroups: pulumi.StringArray{securityGroup.ID()},
					Tags: pulumi.StringMap{
            "Name": pulumi.String("dash-days-control-plane-node"),
					},
				})
				if err != nil {
					return err
				}
        _, err = ec2_classic.NewInstance(ctx, "test_agent_node", &ec2_classic.InstanceArgs{
          Ami:          pulumi.String(RKE2_AMI_ID),
          InstanceType: pulumi.String("c5.xlarge"),
          UserData:     pulumi.String(getUserData(ip, "true", rke2JoinToken, DEFAULT_USER, "cluster.foo.bar")),
          SubnetId:     pulumi.String(ids[0]),
          KeyName:      keyPair.KeyName,
          VpcSecurityGroupIds: pulumi.StringArray{securityGroup.ID()},
          //SecurityGroups: pulumi.StringArray{securityGroup.ID()},
          Tags: pulumi.StringMap{
            "Name": pulumi.String("dash-days-agent-node"),
          },
        })

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

func getRandomToken() string {
	chars := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"
	length := 40

	b := make([]byte, length)
	rand.Read(b)

	for i := 0; i < length; i++ {
		b[i] = chars[int(b[i])%len(chars)]
	}

	return string(b)
}

func getUserData(bootstrapIp string, agentNode string, rke2JoinToken string, defaultUser string, clusterSans string) string {
	return fmt.Sprintf(`#!/bin/bash

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
    ./root/rke2-startup.sh -t %s ${san_options} -s ${bootstrap_ip} -u %s -a
else
    ./root/rke2-startup.sh -t %s ${san_options} -s ${bootstrap_ip} -u %s
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
