import benchmark_flow as b
# New expressions, not used for implementation tuning; not externally curated.
b.CASES={'rotate_right':'(x>>11)|(x<<21)','or_high':'x|0x8000u','div7':'x/7u','div5':'x/5u','unsigned_min':'x<123u?x:123u','unsigned_max':'x>1000u?x:1000u','bit_select':'x&4u?x+9u:x-5u','mix2':'(x*23u)^(x>>13)','high_byte':'x^0x8000u','mask2':'x&0xffff00ffu','signed_cmp':'(int32_t)x<0?11u:22u','variable_rotate':'(x<<(x&31))|(x>>((0u-x)&31))'}
if __name__=='__main__':
 import json
 print(json.dumps(b.run(),indent=2))
