/* Fixed synthetic contract test vector; no XPC, signing, files, or secrets. */
#include "ReviewedTransactionContract.h"
#include <stdio.h>
int main(void){
    char id[65]={0};
    const bool good=bbx_reviewed_transaction_id(
        "123e4567-e89b-42d3-a456-426614174000","import",
        "bbx-test-reviewed.txt",39,
        "661a096ac3bcad82021fdc5db4aff8358cc011409053809e9ebd19b0b81d6be3",
        "abcdef12-3456-4789-8abc-123456789abc",
        INT64_C(1790000000000),INT64_C(1790000060000),id);
    if(!good || !bbx_reviewed_equal_hash(id,id))return 87;
    if(bbx_reviewed_transaction_id(
        "NOT_A_UUID","import","bbx-test-reviewed.txt",39,
        "661a096ac3bcad82021fdc5db4aff8358cc011409053809e9ebd19b0b81d6be3",
        "abcdef12-3456-4789-8abc-123456789abc",
        INT64_C(1790000000000),INT64_C(1790000060000),id))return 88;
    // Recompute the same valid input after negative case.
    if(!bbx_reviewed_transaction_id(
        "123e4567-e89b-42d3-a456-426614174000","import",
        "bbx-test-reviewed.txt",39,
        "661a096ac3bcad82021fdc5db4aff8358cc011409053809e9ebd19b0b81d6be3",
        "abcdef12-3456-4789-8abc-123456789abc",
        INT64_C(1790000000000),INT64_C(1790000060000),id))return 89;
    puts(id);
    return 0;
}
