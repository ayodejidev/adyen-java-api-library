/*
 * Adyen Payout API
 *
 * The version of the OpenAPI document: 68
 * Contact: developer-experience@adyen.com
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */

package com.adyen.service.payout;

import com.adyen.Client;
import com.adyen.Service;
import com.adyen.constants.ApiConstants;
import com.adyen.model.payout.ServiceError;
import com.adyen.model.payout.StoreDetailAndSubmitRequest;
import com.adyen.model.payout.StoreDetailAndSubmitResponse;
import com.adyen.model.payout.StoreDetailRequest;
import com.adyen.model.payout.StoreDetailResponse;
import com.adyen.model.payout.SubmitRequest;
import com.adyen.model.payout.SubmitResponse;
import com.adyen.model.RequestOptions;
import com.adyen.service.exception.ApiException;
import com.adyen.service.resource.Resource;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class InitializationApi extends Service {
    private final String baseURL;

    public InitializationApi(Client client) {
        super(client);
        this.baseURL = createBaseURL("https://pal-test.adyen.com/pal/servlet/Payout/v68");
    }

    /**
    * Store payout details
    *
    * @param storeDetailRequest {@link StoreDetailRequest }  (required)
    * @return {@link StoreDetailResponse }
    * @throws ApiException if fails to make API call
    */
    public StoreDetailResponse storeDetail(StoreDetailRequest storeDetailRequest) throws ApiException, IOException {
        return storeDetail(storeDetailRequest, null);
    }

    /**
    * Store payout details
    *
    * @param storeDetailRequest {@link StoreDetailRequest }  (required)
    * @param requestOptions {@link RequestOptions } Object to store additional data such as idempotency-keys (optional)
    * @return {@link StoreDetailResponse }
    * @throws ApiException if fails to make API call
    */
    public StoreDetailResponse storeDetail(StoreDetailRequest storeDetailRequest, RequestOptions requestOptions) throws ApiException, IOException {

        String requestBody = storeDetailRequest.toJson();
        Resource resource = new Resource(this, this.baseURL + "/storeDetail", null);
        String jsonResult = resource.request(requestBody, requestOptions, ApiConstants.HttpMethod.POST, null);
        return StoreDetailResponse.fromJson(jsonResult);
    }

    /**
    * Store details and submit a payout
    *
    * @param storeDetailAndSubmitRequest {@link StoreDetailAndSubmitRequest }  (required)
    * @return {@link StoreDetailAndSubmitResponse }
    * @throws ApiException if fails to make API call
    */
    public StoreDetailAndSubmitResponse storeDetailAndSubmitThirdParty(StoreDetailAndSubmitRequest storeDetailAndSubmitRequest) throws ApiException, IOException {
        return storeDetailAndSubmitThirdParty(storeDetailAndSubmitRequest, null);
    }

    /**
    * Store details and submit a payout
    *
    * @param storeDetailAndSubmitRequest {@link StoreDetailAndSubmitRequest }  (required)
    * @param requestOptions {@link RequestOptions } Object to store additional data such as idempotency-keys (optional)
    * @return {@link StoreDetailAndSubmitResponse }
    * @throws ApiException if fails to make API call
    */
    public StoreDetailAndSubmitResponse storeDetailAndSubmitThirdParty(StoreDetailAndSubmitRequest storeDetailAndSubmitRequest, RequestOptions requestOptions) throws ApiException, IOException {

        String requestBody = storeDetailAndSubmitRequest.toJson();
        Resource resource = new Resource(this, this.baseURL + "/storeDetailAndSubmitThirdParty", null);
        String jsonResult = resource.request(requestBody, requestOptions, ApiConstants.HttpMethod.POST, null);
        return StoreDetailAndSubmitResponse.fromJson(jsonResult);
    }

    /**
    * Submit a payout
    *
    * @param submitRequest {@link SubmitRequest }  (required)
    * @return {@link SubmitResponse }
    * @throws ApiException if fails to make API call
    */
    public SubmitResponse submitThirdParty(SubmitRequest submitRequest) throws ApiException, IOException {
        return submitThirdParty(submitRequest, null);
    }

    /**
    * Submit a payout
    *
    * @param submitRequest {@link SubmitRequest }  (required)
    * @param requestOptions {@link RequestOptions } Object to store additional data such as idempotency-keys (optional)
    * @return {@link SubmitResponse }
    * @throws ApiException if fails to make API call
    */
    public SubmitResponse submitThirdParty(SubmitRequest submitRequest, RequestOptions requestOptions) throws ApiException, IOException {

        String requestBody = submitRequest.toJson();
        Resource resource = new Resource(this, this.baseURL + "/submitThirdParty", null);
        String jsonResult = resource.request(requestBody, requestOptions, ApiConstants.HttpMethod.POST, null);
        return SubmitResponse.fromJson(jsonResult);
    }
}
