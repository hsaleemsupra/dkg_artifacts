use crate::{impl_timestamp, nanoseconds_since_unix_epoch, TimeStampTrait, Timestamp};
use std::marker::PhantomData;
use std::time::Duration;

trait ExampleTrait {}

struct ExampleStruct<T: ExampleTrait> {
    custom_field: Timestamp, // Time in nano second since linux epoch
    t_marker: PhantomData<T>,
}

impl_timestamp!(custom_field, ExampleStruct<T: ExampleTrait>);

impl<T: ExampleTrait> ExampleStruct<T> {
    fn new() -> Self {
        Self {
            custom_field: nanoseconds_since_unix_epoch(),
            t_marker: Default::default(),
        }
    }

    fn expected_created_time(&self) -> Timestamp {
        self.custom_field
    }

    fn expected_elapsed_time(&self) -> Duration {
        Duration::from_nanos(nanoseconds_since_unix_epoch() as u64)
            .saturating_sub(Duration::from_nanos(self.custom_field as u64))
    }
}

struct TestStruct;
impl ExampleTrait for TestStruct {}

#[test]
fn test_example_3() {
    let test_struct = ExampleStruct::<TestStruct>::new();
    assert!(test_struct.created_time() > Duration::from_nanos(0).as_nanos());
    assert!(test_struct.elapsed_time() > Duration::from_nanos(0));
    assert_eq!(
        test_struct.created_time(),
        test_struct.expected_created_time()
    );
    assert!(test_struct.elapsed_time() <= test_struct.expected_elapsed_time());
}
