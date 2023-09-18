init:
	terraform init

plan:
	terraform plan -out tfplan

show:
	terraform show -json tfplan > tfplan.json

graph:
	terraform graph -type plan -plan tfplan > tfplan-graph.gv

apply:
	terraform apply tfplan --auto-approve

destroy:
	terraform destroy --auto-approve 

tm: init plan show graph

all: init plan show graph apply
