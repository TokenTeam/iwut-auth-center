package mail

var (
	verifyCodeTemplate string = `<body>
    <table width="100%" border="0" cellspacing="0" cellpadding="0">
        <tbody>
            <tr>
                <td class="p-80 mpy-35 mpx-15" bgcolor="#FFFFFF" style="padding: 80px;">
                    <table width="100%" border="0" cellspacing="0" cellpadding="0">
                        <tbody>
                            <tr>
                                <td class="img pb-45"
                                    style="font-size:0pt; line-height:0pt; text-align:left;margin: -100pt;text-align: center;min-width: 600px">
                                    <!-- @*<img src="./Uni.png" width="200" height="200" border="0" style="margin: -50px 0;">*@ -->
                                    <svg width="265" height="73" xmlns="http://www.w3.org/2000/svg" version="1.1">
                                        <g>
                                            <title>background</title>
                                            <rect fill="none" id="canvas_background" height="75" width="267" y="-1" x="-1" />
                                        </g>
                                        <g>
                                            <title>Layer 1</title>
                                            <g stroke="null" id="surface1">
                                                <path stroke="null" id="svg_1" fill-rule="evenodd" fill="rgb(0%,0%,0%)" d="m0,70.999992l0,-70.999992l60.61327,0l0,70.999992l-60.61327,0zm43.142598,-60.441803c-1.401664,1.271956 -2.802164,2.543912 -4.202662,3.814501l-1.135793,1.0315l3.666252,3.382772l5.21951,-11.448966l-3.547308,3.220192zm9.032693,26.010196c0.004666,-1.557498 0.009329,-3.114993 0.015162,-4.671124c0.001164,-0.271878 0.001164,-0.60797 -0.076966,-0.766454c-0.054806,-0.11203 -0.209898,-0.255485 -0.3475,-0.382543c-5.407255,-5.018143 -10.815677,-10.037657 -16.2241,-15.0558l-0.598213,-0.554688c-0.279867,-0.259584 -0.627367,-0.583379 -0.876915,-1.05336c-0.307853,-0.583379 -0.377821,-1.225502 -0.432627,-1.741938l-0.42563,-3.993477c-1.15445,1.394919 -2.368373,2.731086 -3.623106,3.988014c-1.23841,1.237799 -2.389362,1.424973 -3.607947,1.623074c-0.303187,0.05055 -0.616871,0.101103 -0.94688,0.169414c-0.782462,0.166679 -1.569587,0.441291 -2.336887,0.817004c-2.629579,1.292448 -4.819535,3.623228 -6.509231,6.928127c-1.468131,2.870439 -2.483815,6.355678 -2.939763,10.080009c-0.423299,3.452453 -0.434959,7.015569 -0.39298,10.045855c0.025655,1.845769 0.015159,3.716133 0.003499,5.525013c-0.006997,1.323874 -0.015159,2.69283 -0.009329,4.041295c0.027987,5.514087 0.043146,10.570486 0.044313,15.42195l29.173757,0c-0.165588,-5.593327 -1.833125,-11.5528 -5.211348,-18.658539c-1.289718,-2.714686 -2.75552,-5.407517 -4.481364,-8.231505c-0.824441,-1.210476 -1.680367,-2.553474 -2.690218,-4.227102l-1.275726,-2.110819l2.128153,0.689945c0.232055,0.075141 0.655353,0.230893 1.240742,0.448122c2.048856,0.755524 6.848569,2.526152 8.616392,2.546644c0.418636,0.006831 0.910732,-0.073777 1.430818,-0.15848l0.053642,-0.009566c1.41216,-0.233625 3.167155,-0.523263 4.427722,0.827933l1.399333,1.496015l1.344527,-0.911273c1.043668,-0.707702 2.085004,-1.415408 3.128672,-2.121746zm67.791849,30.92724l0,-18.901726l-16.136641,0l0,-38.175066l-16.137805,0l0,57.076792l32.274446,0zm19.286306,-57.076792l-16.136641,0l0,57.076792l16.136641,0l0,-57.076792zm26.449723,0l-16.136641,0l0,57.076792l16.136641,0l0,-57.076792zm3.148497,18.903094l0,-18.903094l32.275613,0l0,57.076792l-16.137805,0l0,-38.173698l-16.137808,0zm91.235339,-18.903094l-48.412254,0l0,18.903094l16.137808,0l0,19.271972l-16.137808,0l0,18.901726l32.276781,0l0,-38.173698l16.135474,0l0,-18.903094zm-221.986667,13.555689c0,0.763719 -0.529415,1.382618 -1.18127,1.382618c-0.651858,0 -1.180106,-0.6189 -1.180106,-1.382618c0,-0.763722 0.528248,-1.383989 1.180106,-1.383989c0.651855,0 1.18127,0.620267 1.18127,1.383989zm224.899611,24.619377l-16.136641,0l0,18.901726l16.136641,0l0,-18.901726zm0,0" />
                                            </g>
                                        </g>
                                    </svg>
                                </td>
                            </tr>
                            <tr>
                                <td>
                                    <table width="100%" border="0" cellspacing="0" cellpadding="0">
                                        <tbody>
                                            <tr>
                                                <td
                                                    style="font-size:20px; line-height:42px; font-family:Arial, sans-serif, 'Motiva Sans'; text-align:left; padding-bottom: 30px; color:#002333; font-weight:bold;">
                                                    <span style="color: #007aff;">同学你好</span>
                                                </td>
                                            </tr>
                                        </tbody>
                                    </table>
                                    <table width="100%" border="0" cellspacing="0" cellpadding="0">
                                        <tbody>
                                            <tr>
                                                <td class="text-18 c-grey4 pb-30"
                                                    style="font-size:18px; line-height:25px; font-family:Arial, sans-serif, 'Motiva Sans'; text-align:left; color:#002333; padding-bottom: 30px;">
                                                    您正在进行验证操作，这是您验证帐户所需的 Uni 令牌验证码，有效时间为 {{ExpireTime}} 分钟。
                                                </td>
                                            </tr>
                                        </tbody>
                                    </table>
                                    <table width="100%" border="0" cellspacing="0" cellpadding="0">
                                        <tbody>
                                            <tr>
                                                <td class="pb-70 mpb-50" style="padding-bottom: 70px;">
                                                    <table width="100%" border="0" cellspacing="0" cellpadding="0"
                                                           bgcolor="#eaebff">
                                                        <tbody>
                                                            <tr>
                                                                <td class="py-30 px-56"
                                                                    style="padding-top: 30px; padding-bottom: 30px; padding-left: 56px; padding-right: 56px;">
                                                                    <table width="100%" border="0" cellspacing="0"
                                                                           cellpadding="0">
                                                                        <tbody>
                                                                            <tr>
                                                                                <td style="font-size:18px; line-height:25px; font-family:Arial, sans-serif, 'Motiva Sans'; color:#8f98a0; text-align:center;">
                                                                                    验证码
                                                                                </td>
                                                                            </tr>
                                                                            <tr>
                                                                                <td style="padding-bottom: 16px"></td>
                                                                            </tr>
                                                                            <tr>
                                                                                <td class="title-48 c-blue1 fw-b a-center"
                                                                                    style="font-size:48px; line-height:52px; font-family:Arial, sans-serif, 'Motiva Sans'; color:#007aff; font-weight:bold; text-align:center;">
                                                                                    {{Captcha}}
                                                                                </td>
                                                                            </tr>
                                                                        </tbody>
                                                                    </table>
                                                                </td>
                                                            </tr>
                                                        </tbody>
                                                    </table>
                                                </td>
                                            </tr>
                                        </tbody>
                                    </table>
                                    <table width="100%" border="0" cellspacing="0" cellpadding="0">
                                    </table>
                                    <table width="100%" border="0" cellspacing="0" cellpadding="0">
                                        <tbody>
                                            <tr>
                                                <td class="title-36 pb-30 c-grey6 fw-b"
                                                    style="font-size:30px; line-height:34px; font-family:Arial, sans-serif, 'Motiva Sans'; text-align:left; padding-bottom: 20px; color:#002333; font-weight:bold;">
                                                    不是您？
                                                </td>
                                            </tr>
                                        </tbody>
                                    </table>
                                    <table width="100%" border="0" cellspacing="0" cellpadding="0">
                                        <tbody>
                                            <tr>
                                                <td class="text-18 c-grey4 pb-30"
                                                    style="font-size:18px; line-height:25px; font-family:Arial, sans-serif, 'Motiva Sans'; text-align:left; color:#002333; padding-bottom: 30px;">
                                                    
                                                    如果这不是来自您的验证请求，请您忽略本邮件并<span style="color: #002333; font-weight: bold;">不要将验证码转发给任何人</span>。<br><br>
                                                    此电子邮件包含一个代码，您需要用它验证您的帐户。切勿与任何人分享此代码。
                                                </td>
                                            </tr>
                                        </tbody>
                                    </table>
                                    <table width="100%" border="0" cellspacing="0" cellpadding="0">
                                        <tbody>
                                            <tr>
                                                <td class="pt-30" style="padding-top: 30px;">
                                                    <table width="100%" border="0" cellspacing="0" cellpadding="0">
                                                        <tbody>
                                                            <tr>
                                                                <td class="img" width="3" bgcolor="#007aff"
                                                                    style="font-size:0pt; line-height:0pt; text-align:left;">
                                                                </td>
                                                                <td class="img" width="37"
                                                                    style="font-size:0pt; line-height:0pt; text-align:left;">
                                                                </td>
                                                                <td>
                                                                    <table width="100%" border="0" cellspacing="0"
                                                                           cellpadding="0">
                                                                        <tbody>
                                                                            <tr>
                                                                                <td class="text-16 py-20 c-grey4 fallback-font"
                                                                                    style="font-size:16px; line-height:22px; font-family:Arial, sans-serif, 'Motiva Sans'; text-align:left; padding-top: 20px; padding-bottom: 20px; color:#002333;">
                                                                                    祝您愉快，<br>
                                                                                    Uni团队
                                                                                </td>
                                                                            </tr>
                                                                        </tbody>
                                                                    </table>
                                                                </td>
                                                            </tr>
                                                        </tbody>
                                                    </table>
                                                </td>
                                            </tr>
                                        </tbody>
                                    </table>
                                </td>
                            </tr>
                        </tbody>
                    </table>
                </td>
            </tr>
            <tr>
            </tr>
        </tbody>
    </table>
</body>`
)
