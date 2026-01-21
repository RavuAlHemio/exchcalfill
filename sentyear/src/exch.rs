use msswap::IdAndChangeKey;
use sxd_document::{Package, QName};
use sxd_document::dom::{Document, Element};


const SOAP_NS: &str = "http://schemas.xmlsoap.org/soap/envelope/";
const MESSAGES_NS: &str = "http://schemas.microsoft.com/exchange/services/2006/messages";
const TYPES_NS: &str = "http://schemas.microsoft.com/exchange/services/2006/types";


macro_rules! name_func {
    ($func_name:ident, $ns_url:expr) => {
        fn $func_name<'s>(name: &'s str) -> QName<'s> {
            QName::with_namespace_uri(Some($ns_url), name)
        }
    };
}
name_func!(soap_name, SOAP_NS);
name_func!(messages_name, MESSAGES_NS);
name_func!(types_name, TYPES_NS);


trait DocumentExt<'d> {
    fn create_text_element<'n, N: Into<QName<'n>>, T: AsRef<str>>(&self, name: N, text: T) -> Element<'d>;
}
impl<'d> DocumentExt<'d> for Document<'d> {
    fn create_text_element<'n, N: Into<QName<'n>>, T: AsRef<str>>(&self, name: N, text: T) -> Element<'d> {
        let elem = self.create_element(name);
        let text_node = self.create_text(text.as_ref());
        elem.append_child(text_node);
        elem
    }
}


fn create_soap_envelope() -> Package {
    let pkg = Package::new();
    let doc = pkg.as_document();

    let root_elem = doc.create_element(soap_name("Envelope"));
    root_elem.set_attribute_value("xmlns:soap", SOAP_NS);
    root_elem.set_attribute_value("xmlns:m", MESSAGES_NS);
    root_elem.set_attribute_value("xmlns:t", TYPES_NS);
    doc.root().append_child(root_elem);

    let body_elem = doc.create_element(soap_name("Body"));
    root_elem.append_child(body_elem);

    pkg
}

fn create_text_elem<'d>(doc: &Document<'d>, name: QName<'d>, text: &str) -> Element<'d> {
    let elem = doc.create_element(name);
    let text_node = doc.create_text(text);
    elem.append_child(text_node);
    elem
}

fn get_soap_body<'d>(doc: Document<'d>) -> Element<'d> {
    let root_elem = doc
        .root()
        .children().into_iter()
        .filter_map(|c| c.element())
        .nth(0).expect("document has no root element");
    if root_elem.name() != soap_name("Envelope") {
        panic!("root element is not a SOAP Envelope");
    }
    root_elem
        .children().into_iter()
        .filter_map(|c| c.element())
        .filter(|e| e.name() == soap_name("Body"))
        .nth(0).expect("SOAP Envelope does not contain a Body")
}


pub fn create_request_enumerate_send_folder(offset: usize) -> Package {
    let pkg = create_soap_envelope();
    let doc = pkg.as_document();
    let body = get_soap_body(doc);

    let find_item_elem = doc.create_element(messages_name("FindItem"));
    find_item_elem.set_attribute_value("Traversal", "Shallow");
    body.append_child(find_item_elem);

    let item_shape_elem = doc.create_element(messages_name("ItemShape"));
    find_item_elem.append_child(item_shape_elem);

    let base_shape_elem = doc.create_text_element(types_name("BaseShape"), "IdOnly");
    item_shape_elem.append_child(base_shape_elem);

    let pagination_elem = doc.create_element(messages_name("IndexedPageViewItemView"));
    pagination_elem.set_attribute_value("BasePoint", "Beginning");
    pagination_elem.set_attribute_value("Offset", &format!("{}", offset));

    let parent_folder_ids_elem = doc.create_element(messages_name("ParentFolderIds"));
    find_item_elem.append_child(parent_folder_ids_elem);

    let dist_folder_id_elem = doc.create_element(types_name("DistinguishedFolderId"));
    dist_folder_id_elem.set_attribute_value("Id", "sentitems");

    pkg
}


pub fn create_request_find_folder(base_folder_id: &IdAndChangeKey, name: &str) -> Package {
    let pkg = create_soap_envelope();
    let doc = pkg.as_document();
    let body = get_soap_body(doc);

    let find_folder_elem = doc.create_element(messages_name("FindFolder"));
    find_folder_elem.set_attribute_value("Traversal", "Deep");
    body.append_child(find_folder_elem);

    let folder_shape_elem = doc.create_element(messages_name("FolderShape"));
    find_folder_elem.append_child(folder_shape_elem);

    let base_shape_elem = doc.create_text_element(types_name("BaseShape"), "IdOnly");
    folder_shape_elem.append_child(base_shape_elem);

    let restriction_elem = doc.create_element(messages_name("Restriction"));
    find_folder_elem.append_child(restriction_elem);

    let is_equal_to_elem = doc.create_element(messages_name("IsEqualTo"));
    restriction_elem.append_child(is_equal_to_elem);

    let field_uri_elem = doc.create_element(types_name("FieldURI"));
    field_uri_elem.set_attribute_value("FieldURI", "folder:DisplayName");
    is_equal_to_elem.append_child(field_uri_elem);

    let field_uri_or_constant_elem = doc.create_element(types_name("FieldURIOrConstant"));
    is_equal_to_elem.append_child(field_uri_or_constant_elem);

    let constant_elem = doc.create_element(types_name("Constant"));
    constant_elem.set_attribute_value("Value", name);
    field_uri_or_constant_elem.append_child(constant_elem);

    let parent_folder_ids_elem = doc.create_element(messages_name("ParentFolderIds"));
    find_folder_elem.append_child(parent_folder_ids_elem);

    let folder_id_elem = doc.create_element(messages_name("FolderId"));
    base_folder_id.set_on_xml_element(&folder_id_elem);

    pkg
}


pub fn create_request_move_item(item_ids: &[IdAndChangeKey], dest_folder_id: &IdAndChangeKey) -> Package {
    let pkg = create_soap_envelope();
    let doc = pkg.as_document();
    let body = get_soap_body(doc);

    let move_item_elem = doc.create_element(messages_name("MoveItem"));
    body.append_child(move_item_elem);

    let to_folder_id_elem = doc.create_element(messages_name("ToFolderId"));
    move_item_elem.append_child(to_folder_id_elem);

    let folder_id_elem = doc.create_element(types_name("FolderId"));
    dest_folder_id.set_on_xml_element(&folder_id_elem);
    to_folder_id_elem.append_child(folder_id_elem);

    let item_ids_elem = doc.create_element(messages_name("ItemIds"));
    move_item_elem.append_child(item_ids_elem);

    for item_id in item_ids {
        let item_id_elem = doc.create_element(types_name("ItemId"));
        item_id.set_on_xml_element(&item_id_elem);
        item_ids_elem.append_child(item_id_elem);
    }

    pkg
}
