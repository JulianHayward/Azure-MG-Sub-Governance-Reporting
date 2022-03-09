function getAzAPICallFunctions {
    $functions = @{
        funcAZAPICall         = $function:AzAPICall.ToString()
        funcCreateBearerToken = $function:createBearerToken.ToString()
        funcGetJWTDetails     = $function:getJWTDetails.ToString()
    }
    return $functions
}