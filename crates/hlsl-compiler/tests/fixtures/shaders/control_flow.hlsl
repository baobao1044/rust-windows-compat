float4 main(float4 pos : SV_Position) : SV_Target {
    float x = pos.x;
    if (x > 0.0) {
        return float4(1.0, 0.0, 0.0, 1.0);
    } else {
        return float4(0.0, 1.0, 0.0, 1.0);
    }
}
