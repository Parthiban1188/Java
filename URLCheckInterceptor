package com.bct.pms.utils;

import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.apache.log4j.Logger;
import org.apache.struts2.ServletActionContext;
import org.apache.struts2.dispatcher.mapper.ActionMapping;

import com.bct.pms.vo.UserPreviligesVO;
import com.opensymphony.xwork2.ActionContext;
import com.opensymphony.xwork2.ActionInvocation;
import com.opensymphony.xwork2.interceptor.Interceptor;

@SuppressWarnings({"serial", "unchecked"})
public class URLCheckInterceptor implements Interceptor {

	private List<String> validateReq = null;

	static Logger logger = Logger.getLogger(URLCheckInterceptor.class);

	public String intercept(ActionInvocation invocation) throws Exception {

		logger.info("Entering URLCheckInterceptor ...");

		ActionContext context = invocation.getInvocationContext();
		HttpServletRequest request = (HttpServletRequest) context
				.get(ServletActionContext.HTTP_REQUEST);
		ActionMapping mapping = (ActionMapping) request
				.getAttribute("struts.actionMapping");
		String actionName = mapping.getMethod() + mapping.getName();
		Map<String, Object> session = ActionContext.getContext().getSession();
		String operCode = ApplicationConstants.PRIVILEGE_DEFAULT_OPERATION;
		if (request.getParameter(ApplicationConstants.PRIVILEGE_OPERATION_CODE) == null) {
			operCode = (String) request.getSession().getAttribute(ApplicationConstants.PRIVILEGE_OPERATION_CODE);
		} else {
			operCode = request.getParameter(ApplicationConstants.PRIVILEGE_OPERATION_CODE);
			request.getSession().setAttribute(ApplicationConstants.PRIVILEGE_OPERATION_CODE, operCode);
		}
		UserPreviligesVO previliges = getPreviliges(operCode);
		request.setAttribute("ROLE_PREVILIGES", previliges);
		session.put("ROLE_PREVILIGES", previliges);

		try {
			logger.info("actionName : " + actionName);

			if (!validateReq.contains(actionName)) {
				validateRequestData(request);
			}

			String userId = ((String) session.get("userId"));

			if (userId == null) {
				List<String> excludeSessionCheck = new ArrayList<String>(19);
				excludeSessionCheck.add("nulllaunchEmpanelWeb");
				excludeSessionCheck.add("nullloadDependantsWeb");
				excludeSessionCheck.add("nullloadCitiesWeb");
				excludeSessionCheck.add("nullchangeStateWeb");
				excludeSessionCheck.add("nullempanelWeb");
				excludeSessionCheck.add("nullactivateAccountOnline");
				excludeSessionCheck.add("nullcaptureDetailsOnline");
				excludeSessionCheck.add("nullrecordDeleteOnline");
				excludeSessionCheck.add("recordDeleteOnline");
				excludeSessionCheck.add("launchEmpanelWeb");
				excludeSessionCheck.add("loadDependantsWeb");
				excludeSessionCheck.add("loadCitiesWeb");
				excludeSessionCheck.add("changeStateWeb");
				excludeSessionCheck.add("empanelWeb");
				excludeSessionCheck.add("activateAccountOnline");
				//Added by Jayaraj
				excludeSessionCheck.add("nullpreAddHospTariffOnline");
				excludeSessionCheck.add("preAddHospTariffOnline");
				excludeSessionCheck.add("addTariffOnline");
				excludeSessionCheck.add("nulladdTariffOnline");
				excludeSessionCheck.add("addNewVersionRoomTariff");
				excludeSessionCheck.add("nulladdNewVersionRoomTariff");
				excludeSessionCheck.add("nulldownloadExcelTariffOnline");
				excludeSessionCheck.add("downloadExcelTariffOnline");
				excludeSessionCheck.add("downloadPdfTariffOnline");
				excludeSessionCheck.add("nulldownloadPdfTariffOnline");
				
				//Added by Jayaraj Ends
				excludeSessionCheck.add("captureDetailsOnline");
				excludeSessionCheck.add("nullupdateOnlineEdit");
				excludeSessionCheck.add("nullskipOnlineEdit");
				excludeSessionCheck.add("updateOnlineEdit");
				excludeSessionCheck.add("skipOnlineEdit");
				excludeSessionCheck.add("nullpreTSTrackStatus");
				excludeSessionCheck.add("preTSTrackStatus");
				excludeSessionCheck.add("showStatusTrackStatus");

				excludeSessionCheck.add("nullgetAutoFillDataPSPRegDetails");
				excludeSessionCheck.add("nullpopBankDeatilPSPRegDetails");
				excludeSessionCheck.add("nullfetchAlfrescoImagePSPRegDetails");			
				excludeSessionCheck.add("preSearchWebInfraDetails");
				excludeSessionCheck.add("nullpreSearchWebInfraDetails");
				excludeSessionCheck.add("webAddWeb");
				excludeSessionCheck.add("nullwebAddWeb");
				excludeSessionCheck.add("requestStatusWeb");
				excludeSessionCheck.add("nullrequestStatusWeb");
				
				excludeSessionCheck.add("loginAuthenticate");
				excludeSessionCheck.add("nullfetchAlfrescoImageAgentEnrollmentEdit");
				excludeSessionCheck.add("goResetAuthenticate");
				excludeSessionCheck.add("nullgoResetAuthenticate");
				excludeSessionCheck.add("nullloadRepository");
				excludeSessionCheck.add("loadRepository");
				excludeSessionCheck.add("searchHospitalDetails");
//exportMasterPDF discount viewPackage document
				
				excludeSessionCheck.add("nulldocumentPremiaUrl");
				excludeSessionCheck.add("nulldiscountPremiaUrl");
				excludeSessionCheck.add("nullviewPackagePremiaUrl");
				excludeSessionCheck.add("nullexportMasterPDFPremiaUrl");
				excludeSessionCheck.add("nullfetchDocumentListPremiaUrl");
				excludeSessionCheck.add("nullfetchAlfrescoImagePremiaHospitalDetails");
				excludeSessionCheck.add("nullshiHospitalSearchSourceMasterDetails");
			    excludeSessionCheck.add("nullpreSearchSourceMasterDetails");
			    excludeSessionCheck.add("SourceMasterDetails");
			    excludeSessionCheck.add("shiHospitalSearchSourceMasterDetails");
			    excludeSessionCheck.add("shiHospitalSearchshiHospitalSearchSourceMasterDetails");
				excludeSessionCheck.add("nulldownloadRepository");
				//Room Tariff
				excludeSessionCheck.add("nulladdTariffUrlRoomTariff");
				excludeSessionCheck.add("nulladdTariffRoomTariff");
				excludeSessionCheck.add("nullviewTariffUrlRoomTariff");
				excludeSessionCheck.add("preAddTariffOnlineRoomTariff");
				excludeSessionCheck.add("nullpreAddTariffOnlineRoomTariff");
				
				excludeSessionCheck.add("nullviewTariffUrlRoomTariff");
				excludeSessionCheck.add("nulltariffClaimsViewPremiaUrl");
				excludeSessionCheck.add("nulldownloadTariffRoomTariff");
				
				excludeSessionCheck.add("nullsaveOTPAuthenticate");
				excludeSessionCheck.add("nullverifyOTPAuthenticate");
				excludeSessionCheck.add("nullupdatePassAuthenticate");
				excludeSessionCheck.add("nulllogoffAuthenticate");  
				excludeSessionCheck.add("nullverifyCurrentstatusOnline");  
				excludeSessionCheck.add("nullUpdateValueAction");
				excludeSessionCheck.add("nullUpdateScriptAction");
				
				/*excludeSessionCheck.add("nullagentsBulkUploadUserMasterDetails");*/
				if (actionName != null && !excludeSessionCheck.contains(actionName)) 
				{
					logger.debug("EXCEPTION_SESSION_TIMEOUT :---: " + actionName);
					return ApplicationConstants.EXCEPTION_SESSION_TIMEOUT;
				}
			}
			
			
		} catch (Exception e) {
			logger.info("Error in intercept(): " + e.getLocalizedMessage());
			if (logger.isDebugEnabled())
				logger.debug(e);
			return ApplicationConstants.EXCEPTION_SECURITY_ERROR;
		}

		return invocation.invoke();
	}

	private UserPreviligesVO getPreviliges(String parameter) {
		logger.debug("GetPreviliges Start...");
		logger.info("Operation Code " + parameter);
		UserPreviligesVO previliges = new UserPreviligesVO();
		if (parameter != null) {
			String[] operations = parameter.split(",");
			for (int i = 0; i < operations.length; i++) {

				if (operations[i].equalsIgnoreCase("0")) {
					previliges.setSearch(true);
				} else if (operations[i].equalsIgnoreCase("1")) {
					previliges.setAdd(true);
				} else if (operations[i].equalsIgnoreCase("2")) {
					previliges.setEdit(true);
				} else if (operations[i].equalsIgnoreCase("3")) {
					previliges.setView(true);
				} else if (operations[i].equalsIgnoreCase("4")) {
					previliges.setDelete(true);
				} else if (operations[i].equalsIgnoreCase("5")) {
					previliges.setReject(true);
				} else if (operations[i].equalsIgnoreCase("6")) {
					previliges.setPrintReprint(true);
				} else if (operations[i].equalsIgnoreCase("7")) {
					previliges.setPreview(true);
				} else if (operations[i].equalsIgnoreCase("8")) {
					previliges.setRunProcess(true);
				} else if (operations[i].equalsIgnoreCase("9")) {
					previliges.setReRunProcess(true);
				} else if (operations[i].equalsIgnoreCase("10")) {
					previliges.setGenerateReport(true);
				} else if (operations[i].equalsIgnoreCase("11")) {
					previliges.setUpload(true);
				} else if (operations[i].equalsIgnoreCase("12")) {
					previliges.setDownload(true);
				} else if (operations[i].equalsIgnoreCase("13")) {
					previliges.setMailNotification(true);
				} else if (operations[i].equalsIgnoreCase("14")) {
					previliges.setUnlock(true);
				} else if (operations[i].equalsIgnoreCase("15")) {
					previliges.setResetPassword(true);
				} else if (operations[i].equalsIgnoreCase("16")) {
					previliges.setResetSession(true);
				} else if (operations[i].equalsIgnoreCase("17")) {
					previliges.setPlannAll(true);
				} else if (operations[i].equalsIgnoreCase("18")) {
					previliges.setPlannSelf(true);
				} else if (operations[i].equalsIgnoreCase("19")) {
					previliges.setAmendment(true);
				} else if (operations[i].equalsIgnoreCase("20")) {
					previliges.setRenewal(true);
				} else if (operations[i].equalsIgnoreCase("21")) {
					previliges.setClosure(true);
				} else if (operations[i].equalsIgnoreCase("22")) {
					previliges.setRevisal(true);
				} else if (operations[i].equalsIgnoreCase("23")) {
					previliges.setIvEdit(true);
				} else if (operations[i].equalsIgnoreCase("24")) {
					previliges.setGradeEdit(true);
				} else if (operations[i].equalsIgnoreCase("25")) {
					previliges.setPackageEdit(true);
				} else if (operations[i].equalsIgnoreCase("26")) {
					previliges.setFinalApproval(true);
				}else if (operations[i].equalsIgnoreCase("27")) {
					previliges.setNetwork(true);
				}else if (operations[i].equalsIgnoreCase("28")) {
					previliges.setEditWorkflow(true);
				}else if (operations[i].equalsIgnoreCase("29")) {
					previliges.setEditFvrWorkFlow(true);
				}else if (operations[i].equalsIgnoreCase("44")) {
					previliges.setHistDetailFvr(true);
				}else if (operations[i].equalsIgnoreCase("45")) {
					previliges.setExportFvr(true);
				}
				else if (operations[i].equalsIgnoreCase("51")) {
					previliges.setHospMasterExportPDF(true);
				}
				else if (operations[i].equalsIgnoreCase("52")) {
					previliges.setHospMasterExportExcel(true);
				}
				else if (operations[i].equalsIgnoreCase("53")) {
					previliges.setHospReqDeEmpExPDF(true);
				}
				else if (operations[i].equalsIgnoreCase("54")) {
					previliges.setHospMastSearchExport(true);
				}
				else if (operations[i].equalsIgnoreCase("55")) {
					previliges.setHospReqPackPDF(true);
				}else if (operations[i].equalsIgnoreCase("56")) {
					previliges.setHospReqPackExcel(true);
				}
				else if (operations[i].equalsIgnoreCase("60")) {
					previliges.setNnwExport(true);
				}
				else if (operations[i].equalsIgnoreCase("61")) {
					previliges.setPremiaRequest(true);
				}
				else if (operations[i].equalsIgnoreCase("62")) {
					previliges.setNnwFreeze(true);
				}
				else if (operations[i].equalsIgnoreCase("63")) {
					previliges.setHospZoneMastSearchExport(true);
				}
				else if (operations[i].equalsIgnoreCase("64")) {
					previliges.setSuspHospFreeze(true);
				}
				else if (operations[i].equalsIgnoreCase("65")) {
					previliges.setFreeze(true);
				}
				else if (operations[i].equalsIgnoreCase("66")) {
					previliges.setUnfreeze(true);
				}
				else if (operations[i].equalsIgnoreCase("68")) {
					previliges.setPackageoveride(true);
				}
				else if (operations[i].equalsIgnoreCase("73")) {
					previliges.setUploadPresentation(true);
				}
				else if (operations[i].equalsIgnoreCase("74")) {
					previliges.setViewPresentation(true);
				}
				else if (operations[i].equalsIgnoreCase("76")) {
					previliges.setVideoDelete(true);
				}
			}
		}
		logger.debug("GetPreviliges End...");

		return previliges;
	}

	protected boolean validateRequestData(HttpServletRequest request) {
		
		boolean req = false;
		
		try {
			logger.info("Entering validateRequestData. Content Type: " + request.getContentType());
			List<String> params = new ArrayList<String>(3);
			params.add("txtLoginPassword");
			params.add("pspHdrVO.website");
			params.add("details.website");
			params.add("hidInnerHtml");
			params.add("entireHtml");
			params.add("pkgVersionVO.disclaimer");
			params.add("starPakgeRateVO.disclaimer");
			request.setCharacterEncoding("windows-1256");
			
			if (request != null) {
				Enumeration<String> enu = request.getParameterNames();
				if (enu != null) {
					for (; enu.hasMoreElements();) {
						String pName = (String) enu.nextElement();
						if (params.contains(pName)) {
							req = true;
						} else if (containsSplChrs(request.getParameter(pName), pName)) {
							logger.error("Request Not Allowed: "
									+ request.getParameter(pName)
									+ " for param:" + pName);
							req = false;
							throw new IllegalArgumentException("Parameter, " + pName + " contains invalid characters");
						} else {
							req = true;
						}
					}
				}
			}
		} catch (UnsupportedEncodingException e) {
			logger.error("UnsupportedEncodingException in validate: " + e);
		} catch (IllegalArgumentException e) {
			throw e;
		} catch (Exception e) {
			logger.info("Error in validating request data: " + e.getMessage());
			e.printStackTrace();
		}

		return req;
	}

	public boolean containsSplChrs(String inputStr, String pName) {
		//system.out.println("::::::::inputStr:::::::::::::"+inputStr+"::::pName::::::::"+pName);
		boolean splchr_flag = true;
		try {
			String pattern = ApplicationConstants.RequestWhitePattern;
			if (inputStr.matches(pattern)) // whitelist check
			{
				splchr_flag = false;
			} else {
				inputStr = inputStr.trim();
				if (inputStr.endsWith("AM") || inputStr.endsWith("PM")) {
					inputStr = inputStr.substring(0, 10);
					if (inputStr.matches(pattern)) {
						splchr_flag = false;
					} else {
						splchr_flag = true;
					}
				} else {
					splchr_flag = true;
				}
			}
		} catch (Exception e) {
			splchr_flag = true;
		}
		if (splchr_flag == false && !pName.equalsIgnoreCase("txtCurrentLoginPassword")
				&& !pName.equalsIgnoreCase("txtNewLoginPassword") && !pName.equalsIgnoreCase("txtRetypeLoginPassword")
				&& !pName.equalsIgnoreCase("loginId") && !pName.equalsIgnoreCase("captchaHash") 
				&& !pName.equalsIgnoreCase("otp") && !pName.equalsIgnoreCase("loginPassword") && !pName.equalsIgnoreCase("hiduserPass") 
				&& !pName.equalsIgnoreCase("hidCurPass") && !pName.equalsIgnoreCase("hidNewPass") && !pName.equalsIgnoreCase("hidConfPass")
				&& !pName.equalsIgnoreCase("hidNewForPass") && !pName.equalsIgnoreCase("hidConfForPass")) {
			// blacklist check
			// String[] splChrs = { "==", "--", "<", ">", "#", "!", "{", "}",
			// "%", "*", "+", "|" };
			String[] splChrs = { "==", "--", "<", ">", "!", "{", "}",
					 "?", "`", "$", "*", "|" };
			for (int i = 0; i < splChrs.length; i++) {

				if (inputStr.indexOf(splChrs[i]) >= 0) {
					splchr_flag = true; // bad character are available
					break;
				}
			}
		}

		return splchr_flag;
	}

	public void init() {

		validateReq = new ArrayList<String>(54);
		validateReq.add("addDisclaimerMasterDetails");
		validateReq.add("updateDisclaimerMasterDetails");
		validateReq.add("preAddDisclaimerMasterDetails");
		validateReq.add("preSearchDisclaimerMasterDetails");
		validateReq.add("preDeleteDisclaimerMasterDetails");
		validateReq.add("preEditDisclaimerMasterDetails.action");
		validateReq.add("searchDisclaimerMasterDetails.action");
		validateReq.add("preViewDisclaimerMasterDetails.action");
		validateReq.add("preAddCourseMasterDetails.action");
		validateReq.add("preDeleteCourseMasterDetails.action");
		validateReq.add("preEditCourseMasterDetails.action");
		validateReq.add("searchCourseMasterDetails.action");
		validateReq.add("addCourseMasterDetails.action");
		validateReq.add("preSearchNotificationMasterDetails");
		validateReq.add("NotificationMasterDetails");
		validateReq.add("fetchPreEditNotificationMasterDetails");
		validateReq.add("addNotificationMasterDetails");
		validateReq.add("updateNotificationMasterDetails");

		validateReq.add("nulllaunchEmpanelWeb");
		validateReq.add("nullloadDependantsWeb");
		validateReq.add("nullloadCitiesWeb");
		validateReq.add("nullempanelWeb");
		validateReq.add("nullactivateAccountOnline");
		validateReq.add("nullcaptureDetailsOnline");
		validateReq.add("nullrecordDeleteOnline");
		validateReq.add("recordDeleteOnline");
		//Added by Jayaraj P
		validateReq.add("nullpreAddHospTariffOnline");
		validateReq.add("preAddHospTariffOnline");
		validateReq.add("addTariffOnline");
		validateReq.add("nulladdTariffOnline");
		validateReq.add("addNewVersionRoomTariff");
		validateReq.add("nulladdNewVersionRoomTariff");
		validateReq.add("downloadExcelTariffOnline");
		validateReq.add("nulldownloadExcelTariffOnline");
		validateReq.add("nulldownloadPdfTariffOnline");
		validateReq.add("downloadPdfTariffOnline");
			
		//Added by Jayaraj P Ends
		validateReq.add("launchEmpanelWeb");
		validateReq.add("loadDependantsWeb");
		validateReq.add("loadCitiesWeb");
		validateReq.add("empanelWeb");
		validateReq.add("activateAccountOnline");
		validateReq.add("captureDetailsOnline");
		validateReq.add("nullupdateOnlineEdit");
		validateReq.add("nullskipOnlineEdit");
		validateReq.add("updateOnlineEdit");
		validateReq.add("skipOnlineEdit");
		validateReq.add("nullTrackStatus");
		validateReq.add("preTSTrackStatus");
		validateReq.add("showStatuseTrackStatus");


		validateReq.add("deleteNotificationMasterDetails");
		validateReq.add("recordDeleteNotificationMasterDetails");
		validateReq.add("nullrecordDeleteNotificationMasterDetails");
		validateReq.add("nulladdNotificationMasterDetails");
		validateReq.add("nullupdateNotificationMasterDetails");
		validateReq.add("nullfetchAlfrescoImageNotificationMasterDetails");
		validateReq.add("addCourseMasterDetails");
		validateReq.add("updateCourseMasterDetails"); 
		validateReq.add("fetchPreSearchCourseMasterDetails"); 
		validateReq.add("nullfetchAlfrescoImageCourseMasterDetails"); 
		validateReq.add("nullrecordDeleteCourseMasterDetails");  
		validateReq.add("deleteCourseMasterDetails");  
		validateReq.add("nullupdateTrainingPlan");
		validateReq.add("nulladdTrainingPlan");
		validateReq.add("nullpreSearchTrainingPlan");
		validateReq.add("preSearchTrainingPlan");
		validateReq.add("nullsearchTrainingPlan");
		validateReq.add("nulladdDetailsTrainingAction");
		validateReq.add("addDetailsTrainingAction");
		validateReq.add("nullfetchAlfrescoImageTrainingAction");
		validateReq.add("fetchAlfrescoImageTrainingAction");
		validateReq.add("preCommitTrainingAction");
		validateReq.add("nulladdContinueTrainingPlan");
		validateReq.add("addContinueTrainingPlan");
		validateReq.add("nullfetchAlfrescoImagePSPRegDetails"); 
		validateReq.add("preSearchPSPEditRegDetails");
		validateReq.add("nullfetchAlfrescoImageAgentEnrollmentEdit");
		validateReq.add("preSearchPSPEditRegDetails");  
		validateReq.add("nullfetchAlfrescoImageAgentEnrollmentEdit");
		validateReq.add("preSearchPSPEditRegDetails");  
		validateReq.add("addInfraAttribute"); 
		validateReq.add("updateInfraAttribute");  
		validateReq.add("searchInfraAttribute");
		validateReq.add("preSearchInfraAttribute"); 
		validateReq.add("searchlookuplistInfraTemplate"); 
		validateReq.add("nullfetchAlfrescoImageHospitalDetails"); 
		validateReq.add("generatePdfPSPRegDetails"); 
		validateReq.add("preSearchPSPRegDetails");  
		validateReq.add("addIvDtlPSPRegDetails"); 
		validateReq.add("updateIvDtlPSPRegDetails");
		validateReq.add("addLabRegistrationNew");
		validateReq.add("nullgetAutoFillDataPSPRegDetails");
		validateReq.add("nullpopBankDeatilPSPRegDetails");
		validateReq.add("nullloadDependantsLabRegistrationNew");
		validateReq.add("addLabRegistrationNew");
		validateReq.add("preSearchLabDetails");
		validateReq.add("nullfetchAlfrescoImageLabDetails"); 
		validateReq.add("addInfraTemplate");  
		validateReq.add("updateInfraTemplate"); 
		validateReq.add("preSearchInfraTemplate");
		validateReq.add("preAddLovMasterDetails");
		validateReq.add("fetchPreEditLovMasterDetails");
		validateReq.add("preSearchLovMasterDetails");
		validateReq.add("fetchPreSearchUserMasterDetails");
		validateReq.add("preAddUserMasterDetails");
		validateReq.add("fetchPreEditUserMasterDetails");
		validateReq.add("fetchPreSearchRoleMasterDetails");
		validateReq.add("fetchPreAddRoleMasterDetails");
		validateReq.add("fetchPreEditRoleMasterDetails");
		
		validateReq.add("preEditPackgeHospPackageAdd");
		validateReq.add("preAddGenHospPackageAdd");
		validateReq.add("preAddNewVersionChangeHospPackage");
		validateReq.add("preEditNewVersionChangeHospPackage");
		validateReq.add("addHospPackageAdd");
		validateReq.add("preEditPackgeHospPackage"); 
		validateReq.add("redirectToOtherActionPSPRegDetails");
		validateReq.add("preSearchStarPakgeRateEdit");
		validateReq.add("preSearchStarPakgeRate");
		validateReq.add("exportStarPakgeRateEdit");
		validateReq.add("updateSendToCust");
		validateReq.add("preEditPackgeSendToCust");
		validateReq.add("preEditPackgecustomerResponseHospitalPack");
		validateReq.add("updateHospcustomerResponseHospitalPack");
		validateReq.add("exportPDFHospPackage");
		validateReq.add("updateUserMasterDetails");
		validateReq.add("addUserMasterDetails");
		validateReq.add("addHospPackageEdit");
		validateReq.add("updatePkgHospPackageEdit");
		validateReq.add("nullfetchPreEditDisclaimerMasterDetails");
		validateReq.add("searchdisDisclaimerMasterDetails");
		validateReq.add("searchNotificatonNotificationMasterDetails");
		validateReq.add("addNewVersionHospPackage");
		validateReq.add("nullpreViewHospPackageEdit");
		
		validateReq.add("nullpreEditPackgeHospPackage");
		validateReq.add("nullpreEditHospPackageEdit");
		validateReq.add("preEditGenHospPackageEdit");
		validateReq.add("nullpreEditGenHospPackageEdit");
		validateReq.add("nullpreEditPackgeHospPackage");
		validateReq.add("nullpreViewHospPackageEdit");
		validateReq.add("nullpreEditPackgeHospPackage");
		validateReq.add("nulladdNewVersionHospPackage");
		validateReq.add("updateNewVersionHospPackage");
		validateReq.add("nullupdateNewVersionHospPackage");
		validateReq.add("nullupdatePkgHospPackageEdit");		
		validateReq.add("nulladdHospPackageAdd");
		validateReq.add("nullsendFinalApprovalHospPackage");
		validateReq.add("sendFinalApprovalHospPackage");
		validateReq.add("redirectToHospReqSearchPSPRegDetails");
		validateReq.add("redirectToHospReqSearchHospitalDetails");
		validateReq.add("redirectToHospReqSearchPSPEditRegDetails");
		validateReq.add("searchHospitalDetailsHospitalDetails");
        validateReq.add("exportExcelHospPackage");
		
		validateReq.add("exportMasterPDFHospitalDetails");
		validateReq.add("exportExcelHospitalDetails");
		
		
		//validateReq.add("nullHospPackageNewVerAdd");
		validateReq.add("addNewVersionHospPackageNewVerAdd");
		
		validateReq.add("nullHospPackageEdit");
		validateReq.add("preAddNewVersionChangeHospPackageNewVerAdd");
		validateReq.add("updateSavePSPEditRegDetails");
		validateReq.add("addSPRHospPackageNewVerAdd");
		validateReq.add("preAddTariffOnlineRoomTariff");
		validateReq.add("nullpreAddTariffOnlineRoomTariff");
		validateReq.add("nullsaveOTPAuthenticate");
		validateReq.add("nullverifyOTPAuthenticate");
		validateReq.add("nullupdatePassAuthenticate");
		validateReq.add("nulllogoffAuthenticate");
		validateReq.add("addPackageOverrideHospPackageAdd");
		validateReq.add("nulladdPackageOverrideHospPackageAdd");
		validateReq.add("nullverifyCurrentstatusOnline");
		validateReq.add("updateShowStatusDetails");
		validateReq.add("updateAmendmentAmendRegDetails");
		validateReq.add("nullUpdateValueAction");
		validateReq.add("nullUpdateScriptAction");
		
	}

	public void destroy() {
	}
}
