package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"time"
)

// EC2 discovers running instances tagged ssh-mcp=enabled.
//
// It shells out to the AWS CLI (already required for the SSM session
// plugin) rather than linking the AWS SDK, which keeps the binary small. The
// arguments are fixed; only Region and Profile come from config.
type EC2 struct {
	Region  string
	Profile string
	// AWSBin defaults to "aws".
	AWSBin string
}

type ec2Out struct {
	Reservations []struct {
		Instances []struct {
			InstanceID string `json:"InstanceId"`
			Tags       []struct {
				Key, Value string
			} `json:"Tags"`
		} `json:"Instances"`
	} `json:"Reservations"`
}

// Hosts implements Source.
func (e *EC2) Hosts(ctx context.Context) ([]Host, error) {
	bin := e.AWSBin
	if bin == "" {
		bin = "aws"
	}
	args := []string{
		"ec2", "describe-instances", "--output", "json",
		"--filters",
		"Name=tag:" + EnableTag + ",Values=" + EnableValue,
		"Name=instance-state-name,Values=running",
	}
	if e.Region != "" {
		args = append(args, "--region", e.Region)
	}
	if e.Profile != "" {
		args = append(args, "--profile", e.Profile)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = nil
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			return nil, fmt.Errorf("aws ec2 describe-instances: %v: %s", err, ee.Stderr)
		}
		return nil, fmt.Errorf("aws ec2 describe-instances: %w", err)
	}
	return parseEC2(out, e.Region, e.Profile)
}

func parseEC2(out []byte, region, profile string) ([]Host, error) {
	var doc ec2Out
	if err := json.Unmarshal(out, &doc); err != nil {
		return nil, fmt.Errorf("parse describe-instances: %w", err)
	}
	var hosts []Host
	for _, r := range doc.Reservations {
		for _, in := range r.Instances {
			tags := map[string]string{}
			for _, t := range in.Tags {
				tags[t.Key] = t.Value
			}
			if tags[EnableTag] != EnableValue { // defence in depth vs the filter
				continue
			}
			name := tags["Name"]
			if name == "" {
				name = in.InstanceID
			}
			hosts = append(hosts, Host{
				ID: in.InstanceID, Name: name, Tags: tags,
				Transport: "ssm", Region: region, Profile: profile,
			})
		}
	}
	return hosts, nil
}
