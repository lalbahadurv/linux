#-- Import modules
import sys
import os.path
import json
import time
from boto import cloudformation

#-- Check for parameters
if len(sys.argv) < 4:
    print "%s:  Error: %s\n" % (sys.argv[0], "Not enough command options given")
    print "Argument 1 (required): AWS Access Key (e.g. ABCDE1FGHIJKL2MNOPQR)"
    print "Argument 2 (required): AWS Secret Access Key (e.g. aBCdE1fGHijKlMn+OPq2RsTUV3wxy45Zab6c+7D8)"
    print "Argument 3 (required): Stack Parameters JSON file (e.g. c:\cloud_formation\cf_stack_parameters.json)"
    print " "
    sys.exit(3)
else:
    pc_access_key = sys.argv[1]
    pc_secret_key = sys.argv[2]
    pc_param_file = sys.argv[3]

#-- Confirm parameters file exists
if os.path.isfile(pc_param_file):
    lo_json_data=open(pc_param_file).read()
else:
    print "Parameters file: " + pc_param_file + " is invalid!"
    print " "
    sys.exit(3)

print "Parameters file: " + pc_param_file
la_parameters_data = json.loads(lo_json_data)
lc_region = la_parameters_data["region_id"]

#-- Connect to AWS region specified in parameters file
print "Connecting to region: " + lc_region
lo_cform_conn = cloudformation.connect_to_region(lc_region, aws_access_key_id=pc_access_key, aws_secret_access_key=pc_secret_key)

#-- Store parameters from file into local variables
lc_stack_name = la_parameters_data["stack_name"]
lc_template_url = la_parameters_data["template_url"]

la_create_stack_parameters = []
la_create_stack_parameters.append(('DeploymentBucket', la_parameters_data["s3_bucket"]))
la_create_stack_parameters.append(('SiteDomain', la_parameters_data["site_domain"]))
la_create_stack_parameters.append(('SiteAdmin', la_parameters_data["site_admin"]))
la_create_stack_parameters.append(('SiteAdminPassword', la_parameters_data["site_admin_password"]))
la_create_stack_parameters.append(('SiteAdminEmail', la_parameters_data["site_admin_email"]))
la_create_stack_parameters.append(('SiteEIP', la_parameters_data["site_eip"]))
la_create_stack_parameters.append(('ServerLicenseFile', la_parameters_data["server_license_file"]))
la_create_stack_parameters.append(('PortalLicenseFile', la_parameters_data["portal_license_file"]))
la_create_stack_parameters.append(('SSLCertificateFile', la_parameters_data["ssl_certificate_file"]))
la_create_stack_parameters.append(('SSLCertPassword', la_parameters_data["ssl_cert_password"]))
la_create_stack_parameters.append(('KeyName', la_parameters_data["key_name"]))
la_create_stack_parameters.append(('InstanceType', la_parameters_data["instance_type"]))

#-- Call CloudFormation API to create the stack
print "Calling CREATE_STACK method to create: " + lc_stack_name
#lc_result = lo_cform_conn.create_stack(stack_name=lc_stack_name, template_body=None, template_url=lc_template_url, parameters=la_create_stack_parameters, capabilities=["CAPABILITY_IAM"])
#print "Output from API call: " + lc_result
print " "

#-- Check the status of the new stack
lo_stacks = lo_cform_conn.describe_stacks(lc_stack_name)
lo_stack = lo_stacks[0]
lc_cur_status = lo_stack.stack_status
print "Current status of stack " + lo_stack.stack_name + ": " + lc_cur_status
for ln_loop in range(1, 9999):
    if "IN_PROGRESS" in lc_cur_status:
        print "\rWaiting for status update(" + str(ln_loop) + ")...",
        time.sleep(1) # pause 1 seconds

        lo_stacks = lo_cform_conn.describe_stacks(lc_stack_name)
        lo_stack = lo_stacks[0]

        if lo_stack.stack_status != lc_cur_status:
            lc_cur_status = lo_stack.stack_status
            print " "
            print "Updated status of stack " + lo_stack.stack_name + ": " + lc_cur_status
    else:
        ln_loop = 10000
