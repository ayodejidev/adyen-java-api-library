/*
 * Legal Entity Management API
 *
 * The version of the OpenAPI document: 3
 * Contact: developer-experience@adyen.com
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.legalentitymanagement;

import java.util.Objects;
import java.util.Arrays;
import com.google.gson.TypeAdapter;
import com.google.gson.annotations.JsonAdapter;
import com.google.gson.annotations.SerializedName;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import io.swagger.annotations.ApiModel;
import io.swagger.annotations.ApiModelProperty;
import java.io.IOException;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonDeserializationContext;
import com.google.gson.JsonDeserializer;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParseException;
import com.google.gson.TypeAdapterFactory;
import com.google.gson.reflect.TypeToken;

import java.lang.reflect.Type;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;

import com.adyen.model.legalentitymanagement.JSON;

/**
 * TransferInstrumentReference
 */

public class TransferInstrumentReference {
  public static final String SERIALIZED_NAME_ACCOUNT_IDENTIFIER = "accountIdentifier";
  @SerializedName(SERIALIZED_NAME_ACCOUNT_IDENTIFIER)
  private String accountIdentifier;

  public static final String SERIALIZED_NAME_ID = "id";
  @SerializedName(SERIALIZED_NAME_ID)
  private String id;

  public static final String SERIALIZED_NAME_REAL_LAST_FOUR = "realLastFour";
  @SerializedName(SERIALIZED_NAME_REAL_LAST_FOUR)
  private String realLastFour;

  public TransferInstrumentReference() { 
  }

  public TransferInstrumentReference accountIdentifier(String accountIdentifier) {
    
    this.accountIdentifier = accountIdentifier;
    return this;
  }

   /**
   * The masked IBAN or bank account number.
   * @return accountIdentifier
  **/
  @ApiModelProperty(required = true, value = "The masked IBAN or bank account number.")

  public String getAccountIdentifier() {
    return accountIdentifier;
  }


  public void setAccountIdentifier(String accountIdentifier) {
    this.accountIdentifier = accountIdentifier;
  }


  public TransferInstrumentReference id(String id) {
    
    this.id = id;
    return this;
  }

   /**
   * The unique identifier of the resource.
   * @return id
  **/
  @ApiModelProperty(required = true, value = "The unique identifier of the resource.")

  public String getId() {
    return id;
  }


  public void setId(String id) {
    this.id = id;
  }


  public TransferInstrumentReference realLastFour(String realLastFour) {
    
    this.realLastFour = realLastFour;
    return this;
  }

   /**
   * Four last digits of the bank account number.
   * @return realLastFour
  **/
  @ApiModelProperty(value = "Four last digits of the bank account number.")

  public String getRealLastFour() {
    return realLastFour;
  }


  public void setRealLastFour(String realLastFour) {
    this.realLastFour = realLastFour;
  }



  @Override
  public boolean equals(Object o) {
    if (this == o) {
      return true;
    }
    if (o == null || getClass() != o.getClass()) {
      return false;
    }
    TransferInstrumentReference transferInstrumentReference = (TransferInstrumentReference) o;
    return Objects.equals(this.accountIdentifier, transferInstrumentReference.accountIdentifier) &&
        Objects.equals(this.id, transferInstrumentReference.id) &&
        Objects.equals(this.realLastFour, transferInstrumentReference.realLastFour);
  }

  @Override
  public int hashCode() {
    return Objects.hash(accountIdentifier, id, realLastFour);
  }

  @Override
  public String toString() {
    StringBuilder sb = new StringBuilder();
    sb.append("class TransferInstrumentReference {\n");
    sb.append("    accountIdentifier: ").append(toIndentedString(accountIdentifier)).append("\n");
    sb.append("    id: ").append(toIndentedString(id)).append("\n");
    sb.append("    realLastFour: ").append(toIndentedString(realLastFour)).append("\n");
    sb.append("}");
    return sb.toString();
  }

  /**
   * Convert the given object to string with each line indented by 4 spaces
   * (except the first line).
   */
  private String toIndentedString(Object o) {
    if (o == null) {
      return "null";
    }
    return o.toString().replace("\n", "\n    ");
  }


  public static HashSet<String> openapiFields;
  public static HashSet<String> openapiRequiredFields;

  static {
    // a set of all properties/fields (JSON key names)
    openapiFields = new HashSet<String>();
    openapiFields.add("accountIdentifier");
    openapiFields.add("id");
    openapiFields.add("realLastFour");

    // a set of required properties/fields (JSON key names)
    openapiRequiredFields = new HashSet<String>();
    openapiRequiredFields.add("accountIdentifier");
    openapiRequiredFields.add("id");
  }

 /**
  * Validates the JSON Object and throws an exception if issues found
  *
  * @param jsonObj JSON Object
  * @throws IOException if the JSON Object is invalid with respect to TransferInstrumentReference
  */
  public static void validateJsonObject(JsonObject jsonObj) throws IOException {
      if (jsonObj == null) {
        if (TransferInstrumentReference.openapiRequiredFields.isEmpty()) {
          return;
        } else { // has required fields
          throw new IllegalArgumentException(String.format("The required field(s) %s in TransferInstrumentReference is not found in the empty JSON string", TransferInstrumentReference.openapiRequiredFields.toString()));
        }
      }

      Set<Entry<String, JsonElement>> entries = jsonObj.entrySet();
      // check to see if the JSON string contains additional fields
      for (Entry<String, JsonElement> entry : entries) {
        if (!TransferInstrumentReference.openapiFields.contains(entry.getKey())) {
          throw new IllegalArgumentException(String.format("The field `%s` in the JSON string is not defined in the `TransferInstrumentReference` properties. JSON: %s", entry.getKey(), jsonObj.toString()));
        }
      }

      // check to make sure all required properties/fields are present in the JSON string
      for (String requiredField : TransferInstrumentReference.openapiRequiredFields) {
        if (jsonObj.get(requiredField) == null) {
          throw new IllegalArgumentException(String.format("The required field `%s` is not found in the JSON string: %s", requiredField, jsonObj.toString()));
        }
      }
      // validate the optional field accountIdentifier
      if (jsonObj.get("accountIdentifier") != null && !jsonObj.get("accountIdentifier").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `accountIdentifier` to be a primitive type in the JSON string but got `%s`", jsonObj.get("accountIdentifier").toString()));
      }
      // validate the optional field id
      if (jsonObj.get("id") != null && !jsonObj.get("id").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `id` to be a primitive type in the JSON string but got `%s`", jsonObj.get("id").toString()));
      }
      // validate the optional field realLastFour
      if (jsonObj.get("realLastFour") != null && !jsonObj.get("realLastFour").isJsonPrimitive()) {
        throw new IllegalArgumentException(String.format("Expected the field `realLastFour` to be a primitive type in the JSON string but got `%s`", jsonObj.get("realLastFour").toString()));
      }
  }

  public static class CustomTypeAdapterFactory implements TypeAdapterFactory {
    @SuppressWarnings("unchecked")
    @Override
    public <T> TypeAdapter<T> create(Gson gson, TypeToken<T> type) {
       if (!TransferInstrumentReference.class.isAssignableFrom(type.getRawType())) {
         return null; // this class only serializes 'TransferInstrumentReference' and its subtypes
       }
       final TypeAdapter<JsonElement> elementAdapter = gson.getAdapter(JsonElement.class);
       final TypeAdapter<TransferInstrumentReference> thisAdapter
                        = gson.getDelegateAdapter(this, TypeToken.get(TransferInstrumentReference.class));

       return (TypeAdapter<T>) new TypeAdapter<TransferInstrumentReference>() {
           @Override
           public void write(JsonWriter out, TransferInstrumentReference value) throws IOException {
             JsonObject obj = thisAdapter.toJsonTree(value).getAsJsonObject();
             elementAdapter.write(out, obj);
           }

           @Override
           public TransferInstrumentReference read(JsonReader in) throws IOException {
             JsonObject jsonObj = elementAdapter.read(in).getAsJsonObject();
             validateJsonObject(jsonObj);
             return thisAdapter.fromJsonTree(jsonObj);
           }

       }.nullSafe();
    }
  }

 /**
  * Create an instance of TransferInstrumentReference given an JSON string
  *
  * @param jsonString JSON string
  * @return An instance of TransferInstrumentReference
  * @throws IOException if the JSON string is invalid with respect to TransferInstrumentReference
  */
  public static TransferInstrumentReference fromJson(String jsonString) throws IOException {
    return JSON.getGson().fromJson(jsonString, TransferInstrumentReference.class);
  }

 /**
  * Convert an instance of TransferInstrumentReference to an JSON string
  *
  * @return JSON string
  */
  public String toJson() {
    return JSON.getGson().toJson(this);
  }
}

