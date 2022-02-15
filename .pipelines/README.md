# [Deprecated] `AzGovViz.yml`

This version of the pipeline is deprecated. All updates will be for the new `AzGovViz.pipeline.yml` pipeline.


## [Deprecated] Edit AzDO YAML file

* Click on '__Repos__'
* Navigate to the AzGovViz Repository
* In the folder '__pipeline__' click on '__AzGovViz.yml__' and click '__Edit__'
* Under the variables section
  * Enter the Service Connection name that you copied earlier (ServiceConnection)
  * Enter the Management Group Id (ManagementGroupId)
* Click '__Commit__'

## [Deprecated] Create AzDO Pipeline

* Click on '__Pipelines__'
* Click on '__New pipeline__'
* Select '__Azure Repos Git__'
* Select the AzGovViz repository
* Click on '__Existing Azure Pipelines YAML file__'
* Under '__Path__' select '__/pipeline/AzGovViz.yml__' (the YAML file we edited earlier)
* Click ' __Save__'
