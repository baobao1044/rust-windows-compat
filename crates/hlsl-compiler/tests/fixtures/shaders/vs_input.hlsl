struct VSInput {
    float3 pos : POSITION;
    float2 uv : TEXCOORD0;
};
struct VSOutput {
    float4 pos : SV_Position;
    float2 uv : TEXCOORD0;
};
VSOutput main(VSInput input) {
    VSOutput o;
    o.pos = float4(input.pos, 1.0);
    o.uv = input.uv;
    return o;
}
