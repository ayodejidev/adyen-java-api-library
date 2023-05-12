/*
 * Adyen BinLookup API
 * The BIN Lookup API provides endpoints for retrieving information, such as cost estimates, and 3D Secure supported version based on a given BIN.  ## Authentication You need an [API credential](https://docs.adyen.com/development-resources/api-credentials) to authenticate to the API.  If using an API key, add an `X-API-Key` header with the API key as the value, for example:   ``` curl -H \"Content-Type: application/json\" \\ -H \"X-API-Key: YOUR_API_KEY\" \\ ... ```  Alternatively, you can use the username and password to connect to the API using basic authentication, for example:  ``` curl -U \"ws@Company.YOUR_COMPANY_ACCOUNT\":\"YOUR_BASIC_AUTHENTICATION_PASSWORD\" \\ -H \"Content-Type: application/json\" \\ ... ```  ## Versioning The BinLookup API supports [versioning](https://docs.adyen.com/development-resources/versioning) using a version suffix in the endpoint URL. This suffix has the following format: \"vXX\", where XX is the version number.  For example: ``` https://pal-test.adyen.com/pal/servlet/BinLookup/v54/get3dsAvailability ```## Going live  To authneticate to the live endpoints, you need an [API credential](https://docs.adyen.com/development-resources/api-credentials) from your live Customer Area.  The live endpoint URLs contain a prefix which is unique to your company account: ```  https://{PREFIX}-pal-live.adyenpayments.com/pal/servlet/BinLookup/v54/get3dsAvailability ```  Get your `{PREFIX}` from your live Customer Area under **Developers** > **API URLs** > **Prefix**.
 *
 * The version of the OpenAPI document: 54
 * Contact: developer-experience@adyen.com
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */

package com.adyen.service;

import com.adyen.Client;
import com.adyen.Service;
import com.adyen.constants.ApiConstants;
import com.adyen.model.binlookup.CostEstimateRequest;
import com.adyen.model.binlookup.CostEstimateResponse;
import com.adyen.model.binlookup.ServiceError;
import com.adyen.model.binlookup.ThreeDSAvailabilityRequest;
import com.adyen.model.binlookup.ThreeDSAvailabilityResponse;
import com.adyen.model.RequestOptions;
import com.adyen.service.exception.ApiException;
import com.adyen.service.resource.Resource;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class BinLookupApi extends Service {
    private final String baseURL;

    public BinLookupApi(Client client) {
        super(client);
        this.baseURL = createBaseURL("https://pal-test.adyen.com/pal/servlet/BinLookup/v54");
    }

    /**
    * Check if 3D Secure is available
    *
    * @param threeDSAvailabilityRequest {@link ThreeDSAvailabilityRequest }  (required)
    * @return {@link ThreeDSAvailabilityResponse }
    * @throws ApiException if fails to make API call
    */
    public ThreeDSAvailabilityResponse get3dsAvailability(ThreeDSAvailabilityRequest threeDSAvailabilityRequest) throws ApiException, IOException {
        return get3dsAvailability(threeDSAvailabilityRequest, null);
    }

    /**
    * Check if 3D Secure is available
    *
    * @param threeDSAvailabilityRequest {@link ThreeDSAvailabilityRequest }  (required)
    * @param requestOptions {@link RequestOptions } Object to store additional data such as idempotency-keys (optional)
    * @return {@link ThreeDSAvailabilityResponse }
    * @throws ApiException if fails to make API call
    */
    public ThreeDSAvailabilityResponse get3dsAvailability(ThreeDSAvailabilityRequest threeDSAvailabilityRequest, RequestOptions requestOptions) throws ApiException, IOException {

        String requestBody = threeDSAvailabilityRequest.toJson();
        Resource resource = new Resource(this, this.baseURL + "/get3dsAvailability", null);
        String jsonResult = resource.request(requestBody, requestOptions, ApiConstants.HttpMethod.POST, null);
        return ThreeDSAvailabilityResponse.fromJson(jsonResult);
    }

    /**
    * Get a fees cost estimate
    *
    * @param costEstimateRequest {@link CostEstimateRequest }  (required)
    * @return {@link CostEstimateResponse }
    * @throws ApiException if fails to make API call
    */
    public CostEstimateResponse getCostEstimate(CostEstimateRequest costEstimateRequest) throws ApiException, IOException {
        return getCostEstimate(costEstimateRequest, null);
    }

    /**
    * Get a fees cost estimate
    *
    * @param costEstimateRequest {@link CostEstimateRequest }  (required)
    * @param requestOptions {@link RequestOptions } Object to store additional data such as idempotency-keys (optional)
    * @return {@link CostEstimateResponse }
    * @throws ApiException if fails to make API call
    */
    public CostEstimateResponse getCostEstimate(CostEstimateRequest costEstimateRequest, RequestOptions requestOptions) throws ApiException, IOException {

        String requestBody = costEstimateRequest.toJson();
        Resource resource = new Resource(this, this.baseURL + "/getCostEstimate", null);
        String jsonResult = resource.request(requestBody, requestOptions, ApiConstants.HttpMethod.POST, null);
        return CostEstimateResponse.fromJson(jsonResult);
    }
}