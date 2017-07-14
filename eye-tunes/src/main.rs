extern crate dmap;
extern crate eye_oPEner;
extern crate reqwest;
extern crate serde;
#[macro_use] extern crate serde_derive;
extern crate serde_json;
#[macro_use] extern crate hyper;
extern crate env_logger;
extern crate plist;
extern crate httpdate;

use std::io::{Read, Cursor};
use std::time::SystemTime;

use reqwest::header::{Headers, Cookie, UserAgent, ContentType};
use reqwest::mime::{Mime, TopLevel, SubLevel};
use dmap::{Parser, from_slice, DmapValue, DmapItem, to_vec};
use dmap::value::ItemName;
use plist::serde::{serialize_to_xml as ser_plist, deserialize as deser_plist};
use eye_oPEner::AppleActionSigner;

header! { (AppleActionSignature, "X-Apple-ActionSignature") => [String] }
header! { (XDsid, "X-Dsid") => [u64] }

#[derive(Deserialize, Debug)]
struct DatabaseSongsWrapper<'a> {
    #[serde(rename = "daap.databasesongs", borrow)]
    databasesongs: DatabaseSongs<'a>,
}


#[derive(Deserialize, Debug)]
struct DatabaseSongs<'a> {
    #[serde(rename = "dmap.status")]
    status: i32,
    #[serde(rename = "dmap.updatetype")]
    update_type: i8,
    #[serde(rename = "dmap.specifiedtotalcount")]
    specified_total_count: i32,
    #[serde(rename = "dmap.returnedcount")]
    returned_count: i32,
    #[serde(rename = "dmap.listing", borrow)]
    listing: Listing<'a>,
}

#[derive(Deserialize, Debug)]
struct Listing<'a> {
    #[serde(rename = "dmap.listingitem", borrow)]
    items: Vec<ListingItem<'a>>,
}

#[derive(Deserialize, Debug)]
struct ListingItem<'a> {
    //#[serde(rename = "dmap.itemkind")]
    //item_kind: i8,
    //#[serde(rename = "daap.songcomposer")]
    //composer: String,
    // ...
    #[serde(rename = "dmap.itemname")]
    name: &'a str,
    #[serde(rename = "daap.songartist")]
    artist: Option<&'a str>,
}



#[derive(Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
struct CloudLibraryUpdateRequest<'a> {
    auto_update: bool,
    cloud_incremental_update: bool,
    cloud_manual_update: bool,
    cuid: &'a str,
    incremental: bool,
    itunes_match_protocol_version: u32,
    itunes_platform: &'a str,
    itunes_version: &'a str,
    library_name: &'a str,
    machine_name: &'a str,
    min_compatible_version: u32,
    min_itunes_match_compatible_version: u32,
    //num_tracks: u32,
    protocol_version: u32,
    sims_are_optional: bool,
    troveid: &'a str,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "kebab-case")]
struct CloudLibraryUpdateResponse {
    cuid: String,
    min_compatible_version: u32,
    protocol_version: u32,
    status: i32,
    troveid: String,
    update_id: String,
    url: String,
}

/*
#[derive(Serialize, Debug)]
#[serde(rename_all = "kebab-case")]
struct UpdateRequest2<'a> {
    auto_update: bool,
    cloud_incremental_update: bool,
    cloud_manual_update: bool,
    cuid: &'a str,
    incremental: bool,
    itunes_match_protocol_version: u32,
    itunes_platform: &'a str,
    itunes_version: &'a str,
    library_name: &'a str,
    machine_name: &'a str,
    min_compatible_version: u32,
    min_itunes_match_compatible_version: u32,
    persistent_library_id: &'a str,
    protocol_version: u32,
    sims_are_optional: bool,
    troveid: &'a str,
}
*/

fn signed_req(client: &reqwest::Client, signer: &mut AppleActionSigner, addr: &str, payload: &[u8]) -> Vec<u8> {
    let mut headers = Headers::new();
    headers.set(UserAgent("iTunes/12.6.1 (Windows; Microsoft Windows 10.0 x64 (Build 14393); x64) AppleWebKit/7603.1030.4006.6".to_owned()));
    headers.set(XDsid(1052721653));
    headers.set_raw("Client-Cloud-DAAP-Version", vec![b"1.3/iTunes-12.6.1.25".to_vec()]);
    headers.set_raw("X-Apple-Cuid", vec![b"1143e9e5f329f9dda99f5330f8179221".to_vec()]);

    headers.set_raw("X-Apple-Tz", vec![b"7200".to_vec()]);
    headers.set_raw("X-Apple-Store-Front", vec![b"143443-4,32".to_vec()]);
    //headers.set_raw("Date", vec![b"Tue, 11 Jul 2017 18:39:43 GMT".to_vec()]);
    headers.set_raw("X-Token", vec![b"AwIAAAECAAHXGQAAAABZSROPtT9ZqShbS/+hWblN546lAZ2NBE0=".to_vec()]);
    headers.set_raw("X-Apple-I-MD-RINFO", vec![b"17106176".to_vec()]);
    headers.set_raw("X-Apple-I-MD-M", vec![b"SKH4ZAY2lGclRT6NHyaqUQdwvKUL2EBBY6P/IZwXGhL7mKwDa1AdpRUYC8zMCNUOmZCLldnn+mlqv8Ne".to_vec()]);
    headers.set_raw("X-Apple-I-MD", vec![b"AAAABQAAABAMO2LRZKaLa9VNm4VvjeMzAAAAAg==".to_vec()]);
    headers.set_raw("Date", vec![httpdate::fmt_http_date(SystemTime::now()).into_bytes()]);

    headers.set(AppleActionSignature(signer.sign(payload).unwrap()));
    headers.set(Cookie(["amp=waA6jEsqhrhuw8C/TTqXV0yP5+Z5w5Kso5vKt+3r/X6Y/7S93bs2dZzGN0XVu96XsGLk6e6RE+latsgZXgV3/3I2adP5AuaYW1kptSdzDgcZRmokMVd4V03PrnzyN54L6N4fyzHbzo+U1MjlBe1uRmhqyUyxEbHzLhaa7xws3bc=", "amia-1052721653=9Oc55b5oyrGtBWTIQbzuJLPrjLz3rdTrBz+RueeH4xI5fhaeZLBZ5RXkftHZrILbK8uVll4FY02Ba9wz2it8sg==", "mt-asn-1052721653=5", "mt-tkn-1052721653=Amu6PhdpHFiaPhfIRikT8yaBVqOmgLVSHl0OfNEWHN32cBK8Wc2XKgYpuEX+Cj2uLYzCA1Y3WYv9geooJA4bf5J6WkN4xajQVi5L9jwO0aJA8IhAJFhr9PpLjLyu6jf+YqtMPGrHQiDW/CBt0vD8iNnpY63qJpL/bdiVt2YF91lS6JLv4kYcXd1lTthF0sih1K6EzIk=", "ns-mzf-inst=36-88-443-109-73-8297-112430-11-st11", "mzf_in=112430", "itspod=11", "xp_ab=1#isj11bm+7652+tK4uhCU1", "xp_abc=tK4uhCU1", "mz_at_ssl-1052721653=AwUAAAECAAHXGQAAAABZJZZb4F/tnFrnzDlDPiBZNSbM/iUgLvc=", "TrPod=7", "mz_at0-1052721653=AwQAAAECAAHXGQAAAABZHv1fIuos42QPIK/7ZrbMZvBEc2gdTy8=", "xp_ci=3z1Ys2WQzHKIz4PkzBr9z1RcZVY1qr", "X-Dsid=1052721653", "s_vi=[CS]v1|2C0BA93385011FCA-60000131A00002F0[CE]"].iter().map(|&x| x.to_owned()).collect()));
    //headers.set(ContentType(Mime(TopLevel::Application, SubLevel::WwwFormUrlEncoded, vec![])));
    headers.set(ContentType(Mime(TopLevel::Application, SubLevel::Ext("x-apple-plist".to_owned()), vec![])));
    let mut resp_buf = Vec::new();
    let mut resp = client.post(addr).body(payload).headers(headers).send().unwrap();
    println!("{:?}", resp);
    resp.read_to_end(&mut resp_buf).unwrap();
    resp_buf
}

fn main() {
    env_logger::init().unwrap();
    eye_oPEner::init().unwrap();
    let client = reqwest::Client::new().unwrap();
    let mut signer = AppleActionSigner::new().unwrap();

    let mut body = Vec::new();
    ser_plist(&mut body, &CloudLibraryUpdateRequest {
        auto_update: false,
        cloud_incremental_update: false,
        cloud_manual_update: false, //true,
        cuid: "1143e9e5f329f9dda99f5330f8179221",
        incremental: false,
        itunes_match_protocol_version: 16,
        itunes_platform: "Windows",
        itunes_version: "12.6.1.25",
        library_name: "Mediathek von eye-tuner",
        machine_name: "DESKTOP-J2E3NJ3",
        min_compatible_version: 1,
        min_itunes_match_compatible_version: 4,
        //num_tracks: 2299,
        protocol_version: 1,
        sims_are_optional: true,
        troveid: "ee4ae618f35ab92e8d2f03c1f5aa0a03",
    }).unwrap();
    let reqtext = plistcvt_apple(body);
    let ret = signed_req(&client, &mut signer, "https://genius-2.itunes.apple.com/WebObjects/UCGovernor.woa/wa/requestCloudLibraryUpdate", reqtext.as_bytes());
    println!("{}", std::str::from_utf8(&ret).unwrap());
    let resp: CloudLibraryUpdateResponse = deser_plist(Cursor::new(ret)).unwrap();
    println!("{:#?}", resp);

    let mut req1 = Plist::read(Cursor::new(reqtext.as_bytes())).unwrap();
    {
        let req1_dict = req1.as_dictionary_mut().unwrap();
        //req1_dict.remove("num-tracks").unwrap();
        //req1_dict.insert("persistent-library-id".to_owned(), Plist::String("B08412F022FE581F".to_owned()));
        req1_dict.insert("persistent-library-id".to_owned(), Plist::String("DAD412F022FE581F".to_owned()));
        req1_dict.insert("process-playlists".to_owned(), Plist::Boolean(true));
        req1_dict.insert("tracks".to_owned(), Plist::Array(Vec::new()));
        req1_dict.insert("playlists".to_owned(), Plist::Array(Vec::new()));
        req1_dict.insert("update-id".to_owned(), Plist::String(resp.update_id.to_owned()));
    }

    let req2 = make_apple_plist(req1.clone()).unwrap();
    let ret2 = signed_req(&client, &mut signer, &resp.url, req2.as_bytes());
    println!("{}", std::str::from_utf8(&ret2).unwrap());
    //let resp: CloudLibraryUpdateResponse = deser_plist(Cursor::new(ret2)).unwrap();
    //println!("{:#?}", resp);


    {
        let req1_dict = req1.as_dictionary_mut().unwrap();
        req1_dict.remove("tracks").unwrap();
        req1_dict.remove("playlists").unwrap();
        req1_dict.remove("persistent-library-id").unwrap();
    }
    
    //loop {
        std::thread::sleep_ms(5000);
        let req3 = make_apple_plist(req1.clone()).unwrap();
        let status = signed_req(&client, &mut signer, "https://genius-2.itunes.apple.com/WebObjects/UCGovernor.woa/wa/checkCloudUpdateStatus", req3.as_bytes());
        println!("{}", std::str::from_utf8(&status).unwrap());
    //}
}


use std::io::Write;

use plist::{Plist, Error};
use plist::xml::EventWriter;

fn plistcvt_apple(buf: Vec<u8>) -> String {
    let text = String::from_utf8(buf).unwrap();
    //let text = text.replace("        ", "\t"); // xD this is necessary
    let text = text.replace("    ", ""); // xD this is necessary
    println!("{}", text);
    text
}

fn make_apple_plist(plist: Plist) -> Result<String, Error> {
    let mut buf = Vec::new();
    {
        let mut writer = EventWriter::new(&mut buf);
        for event in plist.into_events() {
            writer.write(&event)?;
        }
    }
    Ok(plistcvt_apple(buf))
}

    /*
    //let body = "session-id=0&revision-number=10002584&delta=10002583&type=music&meta=all";
    let body = "session-id=0&type=music&meta=all";
    //let body = "session-id=0&type=music&meta=dmap.itemid,dmap.itemname,daap.songartist";
    //&revision-number=10002584&delta=10002583&type=music&meta=all";

    /*
    let form = [
        ("session-id", "0"),
        ("revision-number", "10002586"),
        ("delta", "10002584"),
        ("type", "music"),
        ("meta", "all"),
    ];*/

    let resp_buf = signed_req(&client, &mut signer, "https://ld-7.itunes.apple.com:443/WebObjects/MZDaap.woa/daap/databases/1/items", body.as_bytes());
    let parser = Parser::new(include_bytes!("content-codes.bin"));
    /*
    let val: DatabaseSongsWrapper = from_slice(&parser, resp_buf.as_slice()).unwrap();
    for song in val.databasesongs.listing.items {
        println!("{} - {}", song.name, song.artist.unwrap_or("<Unknown artist>"));
    }*/

    
    let val: DmapItem = from_slice(&parser, resp_buf.as_slice()).unwrap();
    //println!("{:#?}", val);
    let mut listingitems = match &val.value {
        &DmapValue::Container(ref c) => match &c[4].value {
            &DmapValue::Container(ref c) =>
            //c.last().unwrap().clone(),
                c,
            _ => unreachable!(),
        },
        _ => unreachable!(),
    }; //  * /
    //println!("{:#?}", listingitem);

    /*
    match &mut listingitem.value {
        &mut DmapValue::Container(ref mut c) =>
            c.push(DmapItem { name: ItemName::Name("daap.songartist"), value: DmapValue::String("cslul") }),
        _ => unreachable!(),
    }*/

    let newval = DmapItem {
        name: ItemName::Code(*b"mebs"),
        value: DmapValue::Container(vec![
            DmapItem { name: ItemName::Name("dmap.utctime"), value: DmapValue::U32(1499696284) },
            DmapItem { name: ItemName::Name("dmap.sessionid"), value: DmapValue::U32(0) },
            DmapItem { name: ItemName::Name("dmap.serverrevision"), value: DmapValue::U32(1) },
            DmapItem { name: ItemName::Name("dmap.itemkind"), value: DmapValue::U32(2) },
            DmapItem { name: ItemName::Name("dmap.listing"), value: DmapValue::Container(listingitems.clone()) },
/*            DmapItem { name: ItemName::Name("dmap.listing"), value: DmapValue::Container(vec![
                listingitem,
            ]) },*/
        ])
    };
    println!("{:#?}", newval);
    let payload = to_vec(&parser, &newval).unwrap();
    let ret2 = signeddaap_req(&client, &mut signer, "https://ld-7.itunes.apple.com:443/WebObjects/MZDaap.woa/daap/databases/1/edit", &payload);
    let daap_ret: DmapItem = from_slice(&parser, &ret2).unwrap();
    println!("{:#?}", daap_ret);
    
    //println!("Hello, world!");
}
*/
