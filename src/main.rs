#[macro_use]
extern crate lopdf;

use std::io::{Read, Write};
use std::ptr::{null, null_mut};
use foreign_types_shared::ForeignType;
use bcder::encode::Values;

fn cvt_p<T>(r: *mut T) -> Result<*mut T, openssl::error::ErrorStack> {
    if r.is_null() {
        Err(openssl::error::ErrorStack::get())
    } else {
        Ok(r)
    }
}

fn cvt(r: libc::c_int) -> Result<libc::c_int, openssl::error::ErrorStack> {
    if r <= 0 {
        Err(openssl::error::ErrorStack::get())
    } else {
        Ok(r)
    }
}

fn main() {
    let cert_bytes = std::fs::read("./cert.pem").unwrap();
    let key_bytes = std::fs::read("./key.pem").unwrap();
    let cert = openssl::x509::X509::from_pem(&cert_bytes).unwrap();
    let key = openssl::pkey::PKey::private_key_from_pem(&key_bytes).unwrap();

    let mut base_file = std::fs::File::open("./dummy.pdf").unwrap();
    let mut base_file_bytes = vec![];
    base_file.read_to_end(&mut base_file_bytes).unwrap();
    let pdf_doc = lopdf::Document::load_mem(&base_file_bytes).unwrap();
    let mut max_id = pdf_doc.max_id;
    let pages = pdf_doc.get_pages();
    let mut new_objects = std::collections::btree_map::BTreeMap::<lopdf::ObjectId, lopdf::Object>::new();

    let catalog = pdf_doc.catalog().unwrap();
    let page_1_id = *(pages.get(&1).unwrap());
    let mut page_1 = pdf_doc.get_object(page_1_id).and_then(lopdf::Object::as_dict).unwrap().clone();

    max_id += 1;
    let font_id = (max_id, 0);
    new_objects.insert(font_id, dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica",
    }.into());

    let page_1_resources = if page_1.has(b"Resources") {
        let r = page_1.get_mut(b"Resources").unwrap();
        if let Ok(r) = r.as_reference() {
            let o = pdf_doc.get_object(r).unwrap().clone();
            new_objects.insert(r, o);
            new_objects.get_mut(&r).unwrap()
        } else {
            r
        }
    } else {
        page_1.set("Resources", dictionary!());
        page_1.get_mut(b"Resources").unwrap()
    }.as_dict_mut().unwrap();

    let page_fonts = match page_1_resources.get_mut(b"Font") {
        Err(_) => {
            max_id += 1;
            let oid = (max_id, 0);
            page_1_resources.set("Font", lopdf::Object::Reference(oid));
            new_objects.insert(oid, dictionary!().into());
            new_objects.get_mut(&oid).unwrap().as_dict_mut().unwrap()
        }
        Ok(lopdf::Object::Reference(oid)) => {
            let oid = *oid;
            let o = pdf_doc.get_object(oid).unwrap().clone();
            new_objects.insert(oid, o);
            new_objects.get_mut(&oid).unwrap().as_dict_mut().unwrap()
        }
        Ok(lopdf::Object::Dictionary(d)) => d,
        _ => unimplemented!()
    };

    if !page_fonts.has(b"F_as207690_esign_Helvetica") {
        page_fonts.set("F_as207690_esign_Helvetica", font_id);
    }

    let mut page_contents = pdf_doc.get_and_decode_page_content(page_1_id).unwrap();

    page_contents.operations.extend(vec![
        lopdf::content::Operation::new("BT", vec![]),
        lopdf::content::Operation::new("Tf", vec!["F_as207690_esign_Helvetica".into(), (10f64).into()]),
        lopdf::content::Operation::new("Td", vec![(100f64).into(), (100f64).into()]),
        lopdf::content::Operation::new("Tj", vec![lopdf::Object::string_literal("Test text")]),
        lopdf::content::Operation::new("ET", vec![]),
    ]);

    max_id += 1;
    let pcid = (max_id, 0);
    new_objects.insert(
        pcid,
        lopdf::Object::Stream(
            lopdf::Stream::new(
                lopdf::dictionary!(),
                page_contents.encode().unwrap(),
            )
        ),
    );
    page_1.set("Contents", lopdf::Object::Reference(pcid));

    let acro_form = if catalog.has(b"AcroForm") {
        let r = catalog.get(b"AcroForm").unwrap();
        if let Ok(r) = r.as_reference() {
            let o = pdf_doc.get_object(r).unwrap().clone();
            new_objects.insert(r, o);
            new_objects.get_mut(&r).unwrap()
        } else {
            let c = catalog.clone();
            let root = pdf_doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
            new_objects.insert(root, c.into());
            new_objects.get_mut(&root).unwrap().as_dict_mut().unwrap().get_mut(b"AcroForm").unwrap()
        }
    } else {
        max_id += 1;
        let afid = (max_id, 0);
        new_objects.insert(afid, dictionary!().into());

        let mut c = catalog.clone();
        c.set("AcroForm", lopdf::Object::Reference(afid));
        let root = pdf_doc.trailer.get(b"Root").unwrap().as_reference().unwrap();
        new_objects.insert(root, c.into());
        new_objects.get_mut(&afid).unwrap()
    }.as_dict_mut().unwrap();

    acro_form.set("SigFlags", lopdf::Object::Integer(3));

    let acro_fields = if acro_form.has(b"Fields") {
        acro_form.get_mut(b"Fields").unwrap().as_array_mut().unwrap()
    } else {
        acro_form.set("Fields", lopdf::Object::Array(vec![]));
        acro_form.get_mut(b"Fields").unwrap().as_array_mut().unwrap()
    };

    max_id += 1;
    let sid = (max_id, 0);
    acro_fields.push(lopdf::Object::Reference(sid));
    max_id += 1;
    let slid = (max_id, 0);
    max_id += 1;
    let dsid = (max_id, 0);

    new_objects.insert(sid, dictionary! {
        "FT" => "Sig",
        "Subtype" => "Widget",
        "Type" => "Annot",
        "Rect" => lopdf::Object::Array(vec![0.0f64.into(), 0.0f64.into(), 0.0f64.into(), 0.0f64.into()]),
        "F" => 132u32,
        "Lock" => lopdf::Object::Reference(slid),
        "V" => lopdf::Object::Reference(dsid),
        "DR" => dictionary!(),
        "MK" => dictionary!(),
        "T" => "Signature2",
        "DA" => "/Helv 10 Tf"
    }.into());
    new_objects.insert(slid, dictionary! {
        "Type" => "SigFieldLock",
        "Action" => "All"
    }.into());
    new_objects.insert(dsid, dictionary! {
        "Type" => "Sig",
        "Filter" => "Adobe.PPKLite",
        "SubFilter" => "ETSI.CAdES.detached",
        "Contents" => lopdf::Object::String(vec![0; 8192], lopdf::StringFormat::Hexadecimal),
        "ByteRange" => lopdf::Object::String(vec![0; 17], lopdf::StringFormat::Hexadecimal),
        "Name" => "Test person",
        "M" => "D:20220304164500Z",
        "Location" => "Test location",
        "Reason" => "Signed with AS207960 eSign",
        "ContactInfo" => "q@as207960.net",
        "Prop_build" => dictionary! {
            "App" => dictionary! {
                "Name" => "AS207960 eSign",
                "REx" => env!("CARGO_PKG_VERSION")
            }
        }
    }.into());

    let page_1_annotations = if page_1.has(b"Annots") {
        let r = page_1.get_mut(b"Annots").unwrap();
        if let Ok(r) = r.as_reference() {
            let o = pdf_doc.get_object(r).unwrap().clone();
            new_objects.insert(r, o);
            new_objects.get_mut(&r).unwrap()
        } else {
            r
        }
    } else {
        page_1.set("Annots", lopdf::Object::Array(vec![]));
        page_1.get_mut(b"Annots").unwrap()
    }.as_array_mut().unwrap();

    page_1_annotations.push(lopdf::Object::Reference(sid));

    new_objects.insert(page_1_id, page_1.into());

    let mut new_bytes = base_file_bytes.clone();

    let mut target = lopdf::writer::CountingWrite {
        bytes_written: new_bytes.len(),
        inner: &mut new_bytes,
    };
    let mut xref = lopdf::xref::Xref::new(new_objects.len() as u32);

    let mut contents_map = Some(std::collections::btree_map::BTreeMap::<lopdf::ObjectId, (u32, u32)>::new());
    for (&oid, object) in &new_objects {
        if object
            .type_name()
            .map(|name| ["ObjStm", "XRef", "Linearized"].contains(&name))
            .ok()
            != Some(true)
        {
            contents_map = lopdf::writer::Writer::write_indirect_object(&mut target, oid, object, &mut xref, contents_map).unwrap();
        }
    }
    let contents_map = contents_map.unwrap();

    let xref_start = target.bytes_written;
    let mut trailer = pdf_doc.trailer.clone();
    lopdf::writer::Writer::write_xref(&mut target, &xref).unwrap();
    trailer.set("Size", i64::from(max_id + 1));
    trailer.set("Prev", pdf_doc.reference_table_start as i64);
    target.write_all(b"trailer\n").unwrap();
    lopdf::writer::Writer::write_dictionary(&mut target, &trailer, None, None).unwrap();
    write!(target, "\nstartxref\n{}\n%%EOF", xref_start).unwrap();

    let contents_range = *contents_map.get(&dsid).unwrap();

    new_bytes[contents_range.1 as usize + 10] = b'[';
    new_bytes.splice(
        contents_range.1 as usize + 12..contents_range.1 as usize + 45,
        format!(" {:010} {:010} {:010}", contents_range.0, contents_range.1, new_bytes.len() - contents_range.1 as usize).bytes()
    );
    new_bytes[contents_range.1 as usize + 45] = b']';

    let signed_bytes = new_bytes[..contents_range.0 as usize].iter().cloned().chain(
        new_bytes[contents_range.1 as usize..].iter().cloned()
    ).collect::<Vec<_>>();

    let signed_bytes_bio = openssl::bio::MemBioSlice::new(&signed_bytes).unwrap();
    let flags = openssl::cms::CMSOptions::DETACHED | openssl::cms::CMSOptions::BINARY |
        openssl::cms::CMSOptions::NOSMIMECAP | openssl::cms::CMSOptions::CADES |
        openssl::cms::CMSOptions::PARTIAL;
    let signature_bytes: Vec<u8> = unsafe {
        let cms = cvt_p(openssl_sys::CMS_sign(
            null_mut(), null_mut(), null_mut(),
            signed_bytes_bio.as_ptr(), flags.bits()
        )).unwrap();
        let si = cvt_p(openssl_sys::CMS_add1_signer(
            cms, cert.as_ptr(), key.as_ptr(),
            openssl_sys::EVP_sha256(), flags.bits()
        )).unwrap();
        cvt(openssl_sys::CMS_final(
            cms, signed_bytes_bio.as_ptr(), null_mut(), flags.bits()
        )).unwrap();
        let sig: &[u8] = std::slice::from_raw_parts(
            openssl_sys::ASN1_STRING_get0_data((*si).signature as *const openssl_sys::ASN1_STRING),
        openssl_sys::ASN1_STRING_length((*si).signature as *const openssl_sys::ASN1_STRING) as usize
        );
        let r = cryptographic_message_syntax::time_stamp_message_http(
            "http://dd-at.ria.ee/tsa", &sig,
            x509_certificate::DigestAlgorithm::Sha256
        ).unwrap();
        if !r.is_success() {
            panic!("Unable to get timestamp");
        }
        let rs = r.signed_data().unwrap().unwrap();
        let rsd = rs.encode_ref().to_captured(bcder::Mode::Der);
        let rsds = rsd.as_slice();
        cvt(openssl_sys::CMS_unsigned_add1_attr_by_NID(
            si, openssl::nid::Nid::ID_SMIME_AA_TIMESTAMPTOKEN.as_raw(),
            16, rsds.as_ptr() as *const u8, rsds.len() as i32
        )).unwrap();
        let l = cvt(openssl_sys::i2d_CMS_ContentInfo(cms, null_mut())).unwrap();
        let mut buf = vec![0; l as usize];
        cvt(openssl_sys::i2d_CMS_ContentInfo(cms, &mut buf.as_mut_ptr())).unwrap();
        buf
    };

    for i in 0..signature_bytes.len() {
        let b_str = format!("{:02x}", signature_bytes[i]);
        let b = b_str.as_bytes();
        new_bytes[contents_range.0 as usize + 1 + (2*i)] = b[0];
        new_bytes[contents_range.0 as usize + 2 + (2*i)] = b[1];
    }

    let mut new_file = std::fs::File::create("./new.pdf").unwrap();
    new_file.write_all(&new_bytes).unwrap();
}
