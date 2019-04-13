use std::fmt::{Debug, Formatter, Result as FormatterResult};
use std::marker::PhantomData;
use std::str;

use chrono::{DateTime, Utc};
use serde;
use serde::de::{Deserialize, DeserializeOwned, Deserializer, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use super::types::helpers::split_language_tag_key;
use super::types::{LocalizedClaim, Seconds};
use super::{
    AddressCountry, AddressLocality, AddressPostalCode, AddressRegion, EndUserBirthday,
    EndUserEmail, EndUserFamilyName, EndUserGivenName, EndUserMiddleName, EndUserName,
    EndUserNickname, EndUserPhoneNumber, EndUserPictureUrl, EndUserProfileUrl, EndUserTimezone,
    EndUserUsername, EndUserWebsiteUrl, FormattedAddress, LanguageTag, StreetAddress,
    SubjectIdentifier,
};

pub trait AdditionalClaims:
    Clone + Debug + DeserializeOwned + PartialEq + Serialize + 'static
{
}

// In order to support serde flatten, this must be an empty struct rather than an empty
// tuple struct.
#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EmptyAdditionalClaims {}
impl AdditionalClaims for EmptyAdditionalClaims {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AddressClaim {
    #[serde(skip_serializing_if = "Option::is_none")]
    formatted: Option<FormattedAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    street_address: Option<StreetAddress>,
    #[serde(skip_serializing_if = "Option::is_none")]
    locality: Option<AddressLocality>,
    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<AddressRegion>,
    #[serde(skip_serializing_if = "Option::is_none")]
    postal_code: Option<AddressPostalCode>,
    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<AddressCountry>,
}
impl AddressClaim {
    field_getters_setters![
        pub self [self] {
            set_formatted -> formatted[Option<FormattedAddress>],
            set_street_address -> street_address[Option<StreetAddress>],
            set_locality -> locality[Option<AddressLocality>],
            set_region -> region[Option<AddressRegion>],
            set_postal_code -> postal_code[Option<AddressPostalCode>],
            set_country -> country[Option<AddressCountry>],
        }
    ];
}

pub trait GenderClaim: Clone + Debug + DeserializeOwned + PartialEq + Serialize + 'static {}

// Public trait for accessing standard claims fields (via IdTokenClaims and UserInfoClaims).
pub trait StandardClaims<GC>: Clone + Debug + DeserializeOwned + PartialEq + Serialize
where
    GC: GenderClaim,
{
    field_getter_setter_decls![
        set_sub -> sub[SubjectIdentifier],
        set_name -> name[Option<LocalizedClaim<EndUserName>>],
        set_given_name -> given_name[Option<LocalizedClaim<EndUserGivenName>>],
        set_family_name ->
            family_name[Option<LocalizedClaim<EndUserFamilyName>>],
        set_middle_name ->
            middle_name[Option<LocalizedClaim<EndUserMiddleName>>],
        set_nickname -> nickname[Option<LocalizedClaim<EndUserNickname>>],
        set_preferred_username -> preferred_username[Option<EndUserUsername>],
        set_profile -> profile[Option<LocalizedClaim<EndUserProfileUrl>>],
        set_picture -> picture[Option<LocalizedClaim<EndUserPictureUrl>>],
        set_website -> website[Option<LocalizedClaim<EndUserWebsiteUrl>>],
        set_email -> email[Option<EndUserEmail>],
        set_email_verified -> email_verified[Option<bool>],
        set_gender -> gender[Option<GC>],
        set_birthday -> birthday[Option<EndUserBirthday>],
        set_zoneinfo -> zoneinfo[Option<EndUserTimezone>],
        set_locale -> locale[Option<LanguageTag>],
        set_phone_number -> phone_number[Option<EndUserPhoneNumber>],
        set_phone_number_verified -> phone_number_verified[Option<bool>],
        set_address -> address[Option<AddressClaim>],
    ];

    fn updated_at(&self) -> Option<Result<DateTime<Utc>, ()>>;
    fn set_updated_at(self, updated_at: Option<&DateTime<Utc>>) -> Self;
}

// Private (fields accessed via IdTokenClaims and UserInfoClaims)
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StandardClaimsImpl<GC>
where
    GC: GenderClaim,
{
    pub sub: SubjectIdentifier,
    pub name: Option<LocalizedClaim<EndUserName>>,
    pub given_name: Option<LocalizedClaim<EndUserGivenName>>,
    pub family_name: Option<LocalizedClaim<EndUserFamilyName>>,
    pub middle_name: Option<LocalizedClaim<EndUserMiddleName>>,
    pub nickname: Option<LocalizedClaim<EndUserNickname>>,
    pub preferred_username: Option<EndUserUsername>,
    pub profile: Option<LocalizedClaim<EndUserProfileUrl>>,
    pub picture: Option<LocalizedClaim<EndUserPictureUrl>>,
    pub website: Option<LocalizedClaim<EndUserWebsiteUrl>>,
    pub email: Option<EndUserEmail>,
    pub email_verified: Option<bool>,
    pub gender: Option<GC>,
    pub birthday: Option<EndUserBirthday>,
    pub zoneinfo: Option<EndUserTimezone>,
    pub locale: Option<LanguageTag>,
    pub phone_number: Option<EndUserPhoneNumber>,
    pub phone_number_verified: Option<bool>,
    pub address: Option<AddressClaim>,
    pub updated_at: Option<Seconds>,
}
impl<'de, GC> Deserialize<'de> for StandardClaimsImpl<GC>
where
    GC: GenderClaim,
{
    ///
    /// Special deserializer that supports [RFC 5646](https://tools.ietf.org/html/rfc5646) language
    /// tags associated with human-readable client metadata fields.
    ///
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct ClaimsVisitor<GC: GenderClaim>(PhantomData<GC>);
        impl<'de, GC> Visitor<'de> for ClaimsVisitor<GC>
        where
            GC: GenderClaim,
        {
            type Value = StandardClaimsImpl<GC>;

            fn expecting(&self, formatter: &mut Formatter) -> FormatterResult {
                formatter.write_str("struct StandardClaimsImpl")
            }
            fn visit_map<V>(self, mut map: V) -> Result<Self::Value, V::Error>
            where
                V: MapAccess<'de>,
            {
                deserialize_fields! {
                    map {
                        [sub]
                        [LanguageTag(name)]
                        [LanguageTag(given_name)]
                        [LanguageTag(family_name)]
                        [LanguageTag(middle_name)]
                        [LanguageTag(nickname)]
                        [Option(preferred_username)]
                        [LanguageTag(profile)]
                        [LanguageTag(picture)]
                        [LanguageTag(website)]
                        [Option(email)]
                        [Option(email_verified)]
                        [Option(gender)]
                        [Option(birthday)]
                        [Option(zoneinfo)]
                        [Option(locale)]
                        [Option(phone_number)]
                        [Option(phone_number_verified)]
                        [Option(address)]
                        [Option(updated_at)]
                    }
                }
            }
        }
        deserializer.deserialize_map(ClaimsVisitor(PhantomData))
    }
}
impl<GC> Serialize for StandardClaimsImpl<GC>
where
    GC: GenderClaim,
{
    fn serialize<SE>(&self, serializer: SE) -> Result<SE::Ok, SE::Error>
    where
        SE: Serializer,
    {
        serialize_fields! {
            self -> serializer {
                [sub]
                [LanguageTag(name)]
                [LanguageTag(given_name)]
                [LanguageTag(family_name)]
                [LanguageTag(middle_name)]
                [LanguageTag(nickname)]
                [Option(preferred_username)]
                [LanguageTag(profile)]
                [LanguageTag(picture)]
                [LanguageTag(website)]
                [Option(email)]
                [Option(email_verified)]
                [Option(gender)]
                [Option(birthday)]
                [Option(zoneinfo)]
                [Option(locale)]
                [Option(phone_number)]
                [Option(phone_number_verified)]
                [Option(address)]
                [Option(updated_at)]
            }
        }
    }
}
