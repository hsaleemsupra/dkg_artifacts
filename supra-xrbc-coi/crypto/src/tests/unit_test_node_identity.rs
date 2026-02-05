#[test]
fn test_node_identity() {
    use crate::traits::NodeIdentityInterface;
    use crate::NodeIdentity;

    let node1 = NodeIdentity::random();
    let node2 = NodeIdentity::random();

    let message1 = "msg 1";
    let message2 = "msg 2";

    let sign_res1 = node1.sign(message1.as_bytes());
    let sign_res2 = node2.sign(message2.as_bytes());

    assert!(sign_res1.is_ok());
    assert!(sign_res2.is_ok());

    let sign1 = sign_res1.unwrap();
    let sign2 = sign_res2.unwrap();

    let verify1 = NodeIdentity::verify(&node1.public_key(), &sign1, message1.as_bytes());
    assert!(verify1.is_ok());

    let verify2 = NodeIdentity::verify(&node1.public_key(), &sign1, message2.as_bytes());
    assert!(verify2.is_err());

    let verify3 = NodeIdentity::verify(&node1.public_key(), &sign2, message1.as_bytes());
    assert!(verify3.is_err());

    let verify4 = NodeIdentity::verify(&node2.public_key(), &sign1, message1.as_bytes());
    assert!(verify4.is_err());
}

#[test]
fn test_node_identity_valid_public_key() {
    use crate::traits::NodeIdentityInterface;
    use crate::NodeIdentity;

    let node1 = NodeIdentity::random();
    assert!(NodeIdentity::is_valid_public_key(&node1.public_key()).is_ok());
}

#[test]
fn test_node_identity_clone() {
    use crate::traits::NodeIdentityInterface;
    use crate::NodeIdentity;

    let node1 = NodeIdentity::random();
    let node1_clone = node1.clone();

    assert!(NodeIdentity::is_valid_public_key(&node1_clone.public_key()).is_ok());

    let message1 = "msg 1";

    let sign_res1 = node1.sign(message1.as_bytes());
    let sign_res2 = node1_clone.sign(message1.as_bytes());

    assert!(sign_res1.is_ok());
    assert!(sign_res2.is_ok());
    assert_eq!(sign_res1.unwrap(), sign_res2.unwrap());
}
