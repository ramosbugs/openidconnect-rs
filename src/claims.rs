use std::collections::HashMap;
use std::fmt::{Debug, Formatter, Result as FormatterResult};
use std::marker::PhantomData;
use std::str;

use chrono::{DateTime, Utc};
use serde;
use serde::de::{Deserialize, DeserializeOwned, Deserializer, MapAccess, Visitor};
use serde::ser::SerializeMap;
use serde::{Serialize, Serializer};

use super::types::helpers::split_language_tag_key;
use super::types::Seconds;
use super::{
    AddressCountry, AddressLocality, AddressPostalCode, AddressRegion, EndUserBirthday,
    EndUserEmail, EndUserGivenName, EndUserMiddleName, EndUserName, EndUserNickname,
    EndUserPhoneNumber, EndUserPictureUrl, EndUserProfileUrl, EndUserTimezone, EndUserUsername,
    EndUserWebsiteUrl, FormattedAddress, LanguageTag, StreetAddress, SubjectIdentifier,
};

pub trait AdditionalClaims: Clone + Debug + DeserializeOwned + PartialEq + Serialize {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct EmptyAdditionalClaims {}
impl AdditionalClaims for EmptyAdditionalClaims {}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct AddressClaim {
    formatted: Option<FormattedAddress>,
    street_address: Option<StreetAddress>,
    locality: Option<AddressLocality>,
    region: Option<AddressRegion>,
    postal_code: Option<AddressPostalCode>,
    country: Option<AddressCountry>,
}
impl AddressClaim {
    field_getters![
        pub self [self] {
            formatted[Option<&FormattedAddress>],
            street_address[Option<&StreetAddress>],
            locality[Option<&AddressLocality>],
            region[Option<&AddressRegion>],
            postal_code[Option<&AddressPostalCode>],
            country[Option<&AddressCountry>],
        }
    ];
}

pub trait GenderClaim: Clone + Debug + DeserializeOwned + PartialEq + Serialize {}

// Public trait for accessing standard claims fields (via IdTokenClaims and UserInfoClaims).
pub trait StandardClaims<GC>: Clone + Debug + DeserializeOwned + PartialEq + Serialize
where
    GC: GenderClaim,
{
    field_getter_decls![
        self {
            sub[&SubjectIdentifier],
            name[Option<&HashMap<Option<LanguageTag>, EndUserName>>],
            given_name[Option<&HashMap<Option<LanguageTag>, EndUserGivenName>>],
            family_name[Option<&HashMap<Option<LanguageTag>, EndUserGivenName>>],
            middle_name[Option<&HashMap<Option<LanguageTag>, EndUserMiddleName>>],
            nickname[Option<&HashMap<Option<LanguageTag>, EndUserNickname>>],
            preferred_username[Option<&EndUserUsername>],
            profile[Option<&HashMap<Option<LanguageTag>, EndUserProfileUrl>>],
            picture[Option<&HashMap<Option<LanguageTag>, EndUserPictureUrl>>],
            website[Option<&HashMap<Option<LanguageTag>, EndUserWebsiteUrl>>],
            email[Option<&EndUserEmail>],
            email_verified[Option<bool>],
            gender[Option<&GC>],
            birthday[Option<&EndUserBirthday>],
            zoneinfo[Option<&EndUserTimezone>],
            locale[Option<&LanguageTag>],
            phone_number[Option<&EndUserPhoneNumber>],
            phone_number_verified[Option<bool>],
            address[Option<&AddressClaim>],
            updated_at[Option<Result<DateTime<Utc>, ()>>],
        }
    ];
}

// Private (fields accessed via IdTokenClaims and UserInfoClaims)
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct StandardClaimsImpl<GC>
where
    GC: GenderClaim,
{
    pub sub: SubjectIdentifier,
    pub name: Option<HashMap<Option<LanguageTag>, EndUserName>>,
    pub given_name: Option<HashMap<Option<LanguageTag>, EndUserGivenName>>,
    pub family_name: Option<HashMap<Option<LanguageTag>, EndUserGivenName>>,
    pub middle_name: Option<HashMap<Option<LanguageTag>, EndUserMiddleName>>,
    pub nickname: Option<HashMap<Option<LanguageTag>, EndUserNickname>>,
    pub preferred_username: Option<EndUserUsername>,
    pub profile: Option<HashMap<Option<LanguageTag>, EndUserProfileUrl>>,
    pub picture: Option<HashMap<Option<LanguageTag>, EndUserPictureUrl>>,
    pub website: Option<HashMap<Option<LanguageTag>, EndUserWebsiteUrl>>,
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
                deserialize_fields!{
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
        serialize_fields!{
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
