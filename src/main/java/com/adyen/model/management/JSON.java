/*
 * Management API
 *
 * The version of the OpenAPI document: 1
 * Contact: developer-experience@adyen.com
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


package com.adyen.model.management;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonParseException;
import com.google.gson.TypeAdapter;
import com.google.gson.internal.bind.util.ISO8601Utils;
import com.google.gson.stream.JsonReader;
import com.google.gson.stream.JsonWriter;
import com.google.gson.JsonElement;
import io.gsonfire.GsonFireBuilder;
import io.gsonfire.TypeSelector;

import okio.ByteString;

import java.io.IOException;
import java.io.StringReader;
import java.lang.reflect.Type;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.ParsePosition;
import java.time.LocalDate;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.Locale;
import java.util.Map;
import java.util.HashMap;

/*
 * A JSON utility class
 *
 * NOTE: in the future, this class may be converted to static, which may break
 *       backward-compatibility
 */
public class JSON {
    private static Gson gson;
    private static boolean isLenientOnJson = false;
    private static DateTypeAdapter dateTypeAdapter = new DateTypeAdapter();
    private static SqlDateTypeAdapter sqlDateTypeAdapter = new SqlDateTypeAdapter();
    private static OffsetDateTimeTypeAdapter offsetDateTimeTypeAdapter = new OffsetDateTimeTypeAdapter();
    private static LocalDateTypeAdapter localDateTypeAdapter = new LocalDateTypeAdapter();
    private static ByteArrayAdapter byteArrayAdapter = new ByteArrayAdapter();

    @SuppressWarnings("unchecked")
    public static GsonBuilder createGson() {
        GsonFireBuilder fireBuilder = new GsonFireBuilder()
        ;
        GsonBuilder builder = fireBuilder.createGsonBuilder();
        return builder;
    }

    private static String getDiscriminatorValue(JsonElement readElement, String discriminatorField) {
        JsonElement element = readElement.getAsJsonObject().get(discriminatorField);
        if (null == element) {
            throw new IllegalArgumentException("missing discriminator field: <" + discriminatorField + ">");
        }
        return element.getAsString();
    }

    /**
     * Returns the Java class that implements the OpenAPI schema for the specified discriminator value.
     *
     * @param classByDiscriminatorValue The map of discriminator values to Java classes.
     * @param discriminatorValue The value of the OpenAPI discriminator in the input data.
     * @return The Java class that implements the OpenAPI schema
     */
    private static Class getClassByDiscriminator(Map classByDiscriminatorValue, String discriminatorValue) {
        Class clazz = (Class) classByDiscriminatorValue.get(discriminatorValue);
        if (null == clazz) {
            throw new IllegalArgumentException("cannot determine model class of name: <" + discriminatorValue + ">");
        }
        return clazz;
    }

    {
        GsonBuilder gsonBuilder = createGson();
        gsonBuilder.registerTypeAdapter(Date.class, dateTypeAdapter);
        gsonBuilder.registerTypeAdapter(java.sql.Date.class, sqlDateTypeAdapter);
        gsonBuilder.registerTypeAdapter(OffsetDateTime.class, offsetDateTimeTypeAdapter);
        gsonBuilder.registerTypeAdapter(LocalDate.class, localDateTypeAdapter);
        gsonBuilder.registerTypeAdapter(byte[].class, byteArrayAdapter);
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.AdditionalSettings.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.AdditionalSettingsResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Address.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Address2.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.AllowedOrigin.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.AllowedOriginsResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Amount.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Amount2.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.AndroidApp.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.AndroidAppsResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.AndroidCertificate.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.AndroidCertificatesResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.ApiCredential.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.ApiCredentialLinks.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.ApplePayInfo.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.BcmcInfo.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.BillingEntitiesResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.BillingEntity.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.CardholderReceipt.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.CartesBancairesInfo.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Company.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.CompanyApiCredential.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.CompanyLinks.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.CompanyUser.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Connectivity.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Contact.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.CreateAllowedOriginRequest.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.CreateApiCredentialResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.CreateCompanyApiCredentialRequest.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.CreateCompanyApiCredentialResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.CreateCompanyUserRequest.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.CreateCompanyUserResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.CreateCompanyWebhookRequest.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.CreateMerchantApiCredentialRequest.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.CreateMerchantRequest.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.CreateMerchantResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.CreateMerchantUserRequest.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.CreateMerchantWebhookRequest.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.CreateUserResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Currency.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.CustomNotification.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.DataCenter.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.EventUrl.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.ExternalTerminalAction.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.GenerateApiKeyResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.GenerateClientKeyResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.GenerateHmacKeyResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.GiroPayInfo.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.GooglePayInfo.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Gratuity.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Hardware.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.IdName.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.InstallAndroidAppDetails.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.InstallAndroidCertificateDetails.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.InvalidField.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.JSONObject.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.JSONPath.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.KlarnaInfo.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Links.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.LinksElement.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.ListCompanyApiCredentialsResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.ListCompanyResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.ListCompanyUsersResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.ListExternalTerminalActionsResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.ListMerchantApiCredentialsResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.ListMerchantResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.ListMerchantUsersResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.ListStoresResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.ListTerminalsResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.ListWebhooksResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Logo.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.MeApiCredential.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Merchant.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.MerchantLinks.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.MinorUnitsMonetaryValue.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.ModelConfiguration.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.ModelFile.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Name.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Name2.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Nexo.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.OfflineProcessing.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Opi.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.OrderItem.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.PaginationLinks.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.PayPalInfo.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.PaymentMethod.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.PaymentMethodResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.PaymentMethodSetupInfo.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.PayoutSettings.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.PayoutSettingsRequest.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.PayoutSettingsResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Profile.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.ReceiptOptions.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.ReceiptPrinting.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.ReleaseUpdateDetails.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.RequestActivationResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.RestServiceError.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.ScheduleTerminalActionsRequest.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.ScheduleTerminalActionsRequestActionDetails.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.ScheduleTerminalActionsResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Settings.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.ShippingLocation.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.ShippingLocationsResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.ShopperStatement.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Signature.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.SofortInfo.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Store.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.StoreCreationRequest.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.StoreCreationWithMerchantCodeRequest.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.StoreSplitConfiguration.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Surcharge.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.SwishInfo.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Terminal.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.TerminalActionScheduleDetail.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.TerminalModelsResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.TerminalOrder.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.TerminalOrderRequest.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.TerminalOrdersResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.TerminalProduct.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.TerminalProductsResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.TerminalSettings.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.TestCompanyWebhookRequest.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.TestOutput.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.TestWebhookRequest.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.TestWebhookResponse.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Timeouts.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.UninstallAndroidAppDetails.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.UninstallAndroidCertificateDetails.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.UpdatableAddress.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.UpdateCompanyApiCredentialRequest.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.UpdateCompanyUserRequest.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.UpdateCompanyWebhookRequest.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.UpdateMerchantApiCredentialRequest.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.UpdateMerchantUserRequest.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.UpdateMerchantWebhookRequest.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.UpdatePaymentMethodInfo.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.UpdatePayoutSettingsRequest.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.UpdateStoreRequest.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Url.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.User.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.Webhook.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.WebhookLinks.CustomTypeAdapterFactory());
        gsonBuilder.registerTypeAdapterFactory(new com.adyen.model.management.WifiProfiles.CustomTypeAdapterFactory());
        gson = gsonBuilder.create();
    }

    /**
     * Get Gson.
     *
     * @return Gson
     */
    public static Gson getGson() {
        return gson;
    }

    /**
     * Set Gson.
     *
     * @param gson Gson
     */
    public static void setGson(Gson gson) {
        JSON.gson = gson;
    }

    public static void setLenientOnJson(boolean lenientOnJson) {
        isLenientOnJson = lenientOnJson;
    }

    /**
     * Serialize the given Java object into JSON string.
     *
     * @param obj Object
     * @return String representation of the JSON
     */
    public static String serialize(Object obj) {
        return gson.toJson(obj);
    }

    /**
     * Deserialize the given JSON string to Java object.
     *
     * @param <T>        Type
     * @param body       The JSON string
     * @param returnType The type to deserialize into
     * @return The deserialized Java object
     */
    @SuppressWarnings("unchecked")
    public static <T> T deserialize(String body, Type returnType) {
        try {
            if (isLenientOnJson) {
                JsonReader jsonReader = new JsonReader(new StringReader(body));
                // see https://google-gson.googlecode.com/svn/trunk/gson/docs/javadocs/com/google/gson/stream/JsonReader.html#setLenient(boolean)
                jsonReader.setLenient(true);
                return gson.fromJson(jsonReader, returnType);
            } else {
                return gson.fromJson(body, returnType);
            }
        } catch (JsonParseException e) {
            // Fallback processing when failed to parse JSON form response body:
            // return the response body string directly for the String return type;
            if (returnType.equals(String.class)) {
                return (T) body;
            } else {
                throw (e);
            }
        }
    }

    /**
     * Gson TypeAdapter for Byte Array type
     */
    public static class ByteArrayAdapter extends TypeAdapter<byte[]> {

        @Override
        public void write(JsonWriter out, byte[] value) throws IOException {
            if (value == null) {
                out.nullValue();
            } else {
                out.value(new String(value));
            }
        }

        @Override
        public byte[] read(JsonReader in) throws IOException {
            switch (in.peek()) {
                case NULL:
                    in.nextNull();
                    return null;
                default:
                    String bytesAsBase64 = in.nextString();
                    ByteString byteString = ByteString.decodeBase64(bytesAsBase64);
                    return byteString.toByteArray();
            }
        }
    }

    /**
     * Gson TypeAdapter for JSR310 OffsetDateTime type
     */
    public static class OffsetDateTimeTypeAdapter extends TypeAdapter<OffsetDateTime> {

        private DateTimeFormatter formatter;

        public OffsetDateTimeTypeAdapter() {
            this(DateTimeFormatter.ISO_OFFSET_DATE_TIME);
        }

        public OffsetDateTimeTypeAdapter(DateTimeFormatter formatter) {
            this.formatter = formatter;
        }

        public void setFormat(DateTimeFormatter dateFormat) {
            this.formatter = dateFormat;
        }

        @Override
        public void write(JsonWriter out, OffsetDateTime date) throws IOException {
            if (date == null) {
                out.nullValue();
            } else {
                out.value(formatter.format(date));
            }
        }

        @Override
        public OffsetDateTime read(JsonReader in) throws IOException {
            switch (in.peek()) {
                case NULL:
                    in.nextNull();
                    return null;
                default:
                    String date = in.nextString();
                    if (date.endsWith("+0000")) {
                        date = date.substring(0, date.length()-5) + "Z";
                    }
                    return OffsetDateTime.parse(date, formatter);
            }
        }
    }

    /**
     * Gson TypeAdapter for JSR310 LocalDate type
     */
    public static class LocalDateTypeAdapter extends TypeAdapter<LocalDate> {

        private DateTimeFormatter formatter;

        public LocalDateTypeAdapter() {
            this(DateTimeFormatter.ISO_LOCAL_DATE);
        }

        public LocalDateTypeAdapter(DateTimeFormatter formatter) {
            this.formatter = formatter;
        }

        public void setFormat(DateTimeFormatter dateFormat) {
            this.formatter = dateFormat;
        }

        @Override
        public void write(JsonWriter out, LocalDate date) throws IOException {
            if (date == null) {
                out.nullValue();
            } else {
                out.value(formatter.format(date));
            }
        }

        @Override
        public LocalDate read(JsonReader in) throws IOException {
            switch (in.peek()) {
                case NULL:
                    in.nextNull();
                    return null;
                default:
                    String date = in.nextString();
                    return LocalDate.parse(date, formatter);
            }
        }
    }

    public static void setOffsetDateTimeFormat(DateTimeFormatter dateFormat) {
        offsetDateTimeTypeAdapter.setFormat(dateFormat);
    }

    public static void setLocalDateFormat(DateTimeFormatter dateFormat) {
        localDateTypeAdapter.setFormat(dateFormat);
    }

    /**
     * Gson TypeAdapter for java.sql.Date type
     * If the dateFormat is null, a simple "yyyy-MM-dd" format will be used
     * (more efficient than SimpleDateFormat).
     */
    public static class SqlDateTypeAdapter extends TypeAdapter<java.sql.Date> {

        private DateFormat dateFormat;

        public SqlDateTypeAdapter() {}

        public SqlDateTypeAdapter(DateFormat dateFormat) {
            this.dateFormat = dateFormat;
        }

        public void setFormat(DateFormat dateFormat) {
            this.dateFormat = dateFormat;
        }

        @Override
        public void write(JsonWriter out, java.sql.Date date) throws IOException {
            if (date == null) {
                out.nullValue();
            } else {
                String value;
                if (dateFormat != null) {
                    value = dateFormat.format(date);
                } else {
                    value = date.toString();
                }
                out.value(value);
            }
        }

        @Override
        public java.sql.Date read(JsonReader in) throws IOException {
            switch (in.peek()) {
                case NULL:
                    in.nextNull();
                    return null;
                default:
                    String date = in.nextString();
                    try {
                        if (dateFormat != null) {
                            return new java.sql.Date(dateFormat.parse(date).getTime());
                        }
                        return new java.sql.Date(ISO8601Utils.parse(date, new ParsePosition(0)).getTime());
                    } catch (ParseException e) {
                        throw new JsonParseException(e);
                    }
            }
        }
    }

    /**
     * Gson TypeAdapter for java.util.Date type
     * If the dateFormat is null, ISO8601Utils will be used.
     */
    public static class DateTypeAdapter extends TypeAdapter<Date> {

        private DateFormat dateFormat;

        public DateTypeAdapter() {}

        public DateTypeAdapter(DateFormat dateFormat) {
            this.dateFormat = dateFormat;
        }

        public void setFormat(DateFormat dateFormat) {
            this.dateFormat = dateFormat;
        }

        @Override
        public void write(JsonWriter out, Date date) throws IOException {
            if (date == null) {
                out.nullValue();
            } else {
                String value;
                if (dateFormat != null) {
                    value = dateFormat.format(date);
                } else {
                    value = ISO8601Utils.format(date, true);
                }
                out.value(value);
            }
        }

        @Override
        public Date read(JsonReader in) throws IOException {
            try {
                switch (in.peek()) {
                    case NULL:
                        in.nextNull();
                        return null;
                    default:
                        String date = in.nextString();
                        try {
                            if (dateFormat != null) {
                                return dateFormat.parse(date);
                            }
                            return ISO8601Utils.parse(date, new ParsePosition(0));
                        } catch (ParseException e) {
                            throw new JsonParseException(e);
                        }
                }
            } catch (IllegalArgumentException e) {
                throw new JsonParseException(e);
            }
        }
    }

    public static void setDateFormat(DateFormat dateFormat) {
        dateTypeAdapter.setFormat(dateFormat);
    }

    public static void setSqlDateFormat(DateFormat dateFormat) {
        sqlDateTypeAdapter.setFormat(dateFormat);
    }
}
