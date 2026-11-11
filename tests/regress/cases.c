/* ISC: see LICENSE. */
#include "harness.h"

void TestChunkSizeMalformed(void);
void TestChunkSizeValid(void);
void TestChunkMissingFinalCRLF(void);
void TestChunkBadTerminator(void);
void TestChunkTruncatedAtBoundaries(void);
void TestChunkedOverridesContentLength(void);
void TestBodyIntegrity(void);
void TestRedirectLocationIsEscapedAndRedacted(void);
void TestErrorMessageRedactsPassword(void);
void TestBodyIsNotEscaped(void);
void TestNumericOptionRanges(void);
void TestRequireSizeZero(void);
void TestHugeTimeoutStillWorks(void);
void TestRedirectHostCannotReachAuthPrompt(void);
void TestTruncatedBody(void);
void TestCloseWithoutResponse(void);
void TestCloseAfterHeaders(void);
void TestTruncatedChunked(void);
void TestInvalidStatusLine(void);
void TestMalformedHeaders(void);
void TestHTTP10NoLength(void);
void TestStallAfterHeadersTimeout(void);
void TestConnectionRefused(void);
void TestDNSFailure(void);
void TestIPv6Literal(void);
void TestForceIPv4(void);
void TestFTPPassive(void);
void TestFTPActive(void);
void TestFTPAuth(void);
void TestFTPMissingFile(void);
void TestFTPRestart(void);
void TestFTPActiveHonoursTimeout(void);
void TestFTPPassiveIgnoresAdvertisedAddress(void);
void TestFTPActiveRejectsOtherPeer(void);
void TestFTPSizeValid(void);
void TestFTPSizeUnknown(void);
void TestFTPSizeOverflow(void);
void TestFTPSizeMalformed(void);
void TestFTPSizeOverflowDownload(void);
void TestFTPUnknownSizeFailure(void);
void TestFTPUnknownSizeSuccess(void);
void TestGETDefaultFilename(void);
void TestGETToStdout(void);
void TestDownloadSizes(void);
void TestOverwriteExisting(void);
void TestOutputIntoDirectory(void);
void TestMtimeFromLastModified(void);
void TestHTTPErrors(void);
void TestRedirects(void);
void TestRedirectLoopGivesUp(void);
void TestNoRedirectFlag(void);
void TestChunked(void);
void TestRequestHeaders(void);
void TestFragmentNotSent(void);
void TestBasicAuth(void);
void TestSizeOnly(void);
void TestExpectedSize(void);
void TestIfModifiedSince(void);
void TestRestart(void);
void TestMirrorSkipsUpToDate(void);
void TestMultipleURLs(void);
void TestTimeout(void);
void TestHTTPProxy(void);
void TestNoProxy(void);
void TestFileScheme(void);
void TestUnwritableOutput(void);
void TestCLIErrors(void);
void TestUnsupportedScheme(void);
void TestNoProxyDomainBoundaries(void);
void TestDeprecatedFlagsWarn(void);
void TestStalledBodyUnknownLengthFails(void);
void TestReplaceDropsSpecialBits(void);
void TestReplacementPrivateWhileDownloading(void);
void TestNewFileDoesNotFollowDanglingSymlink(void);
void TestResumeNewFileNoFollow(void);
void TestNewFileModeAndNoDebris(void);
void TestReplaceSymlinkLeavesTarget(void);
void TestTruncatedReplacementLeavesNoDebris(void);
void TestResumeWellFormedRange(void);
void TestResumeMalformedRangeNeverCorrupts(void);
void TestResumeThroughSymlink(void);
void TestPlainDownloadReplacesSymlink(void);
void TestResumeCompleteReadOnlyFile(void);
void TestResumePartialReadOnlyFileFails(void);
void TestResumeTargetIsTheMeasuredFile(void);
void TestRedirectCredentialsStayInOrigin(void);
void TestRedirectCredentialsSameOrigin(void);
void TestPassivePortrangeDefault(void);
void TestWriteErrorIsReported(void);
void TestWriteErrorToStdout(void);
void TestAutoRetryProducesExactContent(void);
void TestAutoRetryToStdout(void);
void TestAutoRetryUsesRange(void);
void TestAutoRetryToDevice(void);
void TestRedirectToFileNotFollowed(void);
void TestStdoutWritesNoFiles(void);
void TestOutputElsewhere(void);
void TestIfModifiedSinceFile(void);
void TestResumeMtimeMismatch(void);
void TestResumePreciousMismatch(void);
void TestReplaceKeepsModeAndLeavesNoTemp(void);
void TestDevNullUnveilsOnlyTheDevice(void);
void TestSOCKS5(void);
void TestSOCKS5Refused(void);
void TestSOCKS5BadVersion(void);
void TestSOCKS5FragmentedReplies(void);
void TestSOCKS5CoalescedReplyKeepsPayload(void);
void TestSOCKS5ReplyAddressTypes(void);
void TestSOCKS5MalformedReply(void);
void TestSOCKS5TrickleHonoursTimeout(void);
void TestTLSUntrustedRejected(void);
void TestTLSNoVerifyPeer(void);
void TestTLSTrustedCA(void);
void TestTLSBinaryIntegrity(void);
void TestTLSHostnameMismatch(void);
void TestTLSPlainServer(void);
void TestVerboseNeverShowsCredentials(void);
void TestVerboseStillAuthenticates(void);
void TestVerboseKeepsOtherHeaders(void);
void TestVerboseNeverShowsNetrcOrFTPPassword(void);

const struct test tests[] = {
	{ "TestChunkSizeMalformed", TestChunkSizeMalformed },
	{ "TestChunkSizeValid", TestChunkSizeValid },
	{ "TestChunkMissingFinalCRLF", TestChunkMissingFinalCRLF },
	{ "TestChunkBadTerminator", TestChunkBadTerminator },
	{ "TestChunkTruncatedAtBoundaries", TestChunkTruncatedAtBoundaries },
	{ "TestChunkedOverridesContentLength", TestChunkedOverridesContentLength },
	{ "TestBodyIntegrity", TestBodyIntegrity },
	{ "TestRedirectLocationIsEscapedAndRedacted", TestRedirectLocationIsEscapedAndRedacted },
	{ "TestErrorMessageRedactsPassword", TestErrorMessageRedactsPassword },
	{ "TestBodyIsNotEscaped", TestBodyIsNotEscaped },
	{ "TestNumericOptionRanges", TestNumericOptionRanges },
	{ "TestRequireSizeZero", TestRequireSizeZero },
	{ "TestHugeTimeoutStillWorks", TestHugeTimeoutStillWorks },
	{ "TestRedirectHostCannotReachAuthPrompt", TestRedirectHostCannotReachAuthPrompt },
	{ "TestTruncatedBody", TestTruncatedBody },
	{ "TestCloseWithoutResponse", TestCloseWithoutResponse },
	{ "TestCloseAfterHeaders", TestCloseAfterHeaders },
	{ "TestTruncatedChunked", TestTruncatedChunked },
	{ "TestInvalidStatusLine", TestInvalidStatusLine },
	{ "TestMalformedHeaders", TestMalformedHeaders },
	{ "TestHTTP10NoLength", TestHTTP10NoLength },
	{ "TestStallAfterHeadersTimeout", TestStallAfterHeadersTimeout },
	{ "TestConnectionRefused", TestConnectionRefused },
	{ "TestDNSFailure", TestDNSFailure },
	{ "TestIPv6Literal", TestIPv6Literal },
	{ "TestForceIPv4", TestForceIPv4 },
	{ "TestFTPPassive", TestFTPPassive },
	{ "TestFTPActive", TestFTPActive },
	{ "TestFTPAuth", TestFTPAuth },
	{ "TestFTPMissingFile", TestFTPMissingFile },
	{ "TestFTPRestart", TestFTPRestart },
	{ "TestFTPActiveHonoursTimeout", TestFTPActiveHonoursTimeout },
	{ "TestFTPPassiveIgnoresAdvertisedAddress", TestFTPPassiveIgnoresAdvertisedAddress },
	{ "TestFTPActiveRejectsOtherPeer", TestFTPActiveRejectsOtherPeer },
	{ "TestFTPSizeValid", TestFTPSizeValid },
	{ "TestFTPSizeUnknown", TestFTPSizeUnknown },
	{ "TestFTPSizeOverflow", TestFTPSizeOverflow },
	{ "TestFTPSizeMalformed", TestFTPSizeMalformed },
	{ "TestFTPSizeOverflowDownload", TestFTPSizeOverflowDownload },
	{ "TestFTPUnknownSizeFailure", TestFTPUnknownSizeFailure },
	{ "TestFTPUnknownSizeSuccess", TestFTPUnknownSizeSuccess },
	{ "TestGETDefaultFilename", TestGETDefaultFilename },
	{ "TestGETToStdout", TestGETToStdout },
	{ "TestDownloadSizes", TestDownloadSizes },
	{ "TestOverwriteExisting", TestOverwriteExisting },
	{ "TestOutputIntoDirectory", TestOutputIntoDirectory },
	{ "TestMtimeFromLastModified", TestMtimeFromLastModified },
	{ "TestHTTPErrors", TestHTTPErrors },
	{ "TestRedirects", TestRedirects },
	{ "TestRedirectLoopGivesUp", TestRedirectLoopGivesUp },
	{ "TestNoRedirectFlag", TestNoRedirectFlag },
	{ "TestChunked", TestChunked },
	{ "TestRequestHeaders", TestRequestHeaders },
	{ "TestFragmentNotSent", TestFragmentNotSent },
	{ "TestBasicAuth", TestBasicAuth },
	{ "TestSizeOnly", TestSizeOnly },
	{ "TestExpectedSize", TestExpectedSize },
	{ "TestIfModifiedSince", TestIfModifiedSince },
	{ "TestRestart", TestRestart },
	{ "TestMirrorSkipsUpToDate", TestMirrorSkipsUpToDate },
	{ "TestMultipleURLs", TestMultipleURLs },
	{ "TestTimeout", TestTimeout },
	{ "TestHTTPProxy", TestHTTPProxy },
	{ "TestNoProxy", TestNoProxy },
	{ "TestFileScheme", TestFileScheme },
	{ "TestUnwritableOutput", TestUnwritableOutput },
	{ "TestCLIErrors", TestCLIErrors },
	{ "TestUnsupportedScheme", TestUnsupportedScheme },
	{ "TestNoProxyDomainBoundaries", TestNoProxyDomainBoundaries },
	{ "TestDeprecatedFlagsWarn", TestDeprecatedFlagsWarn },
	{ "TestStalledBodyUnknownLengthFails", TestStalledBodyUnknownLengthFails },
	{ "TestReplaceDropsSpecialBits", TestReplaceDropsSpecialBits },
	{ "TestReplacementPrivateWhileDownloading", TestReplacementPrivateWhileDownloading },
	{ "TestNewFileDoesNotFollowDanglingSymlink", TestNewFileDoesNotFollowDanglingSymlink },
	{ "TestResumeNewFileNoFollow", TestResumeNewFileNoFollow },
	{ "TestNewFileModeAndNoDebris", TestNewFileModeAndNoDebris },
	{ "TestReplaceSymlinkLeavesTarget", TestReplaceSymlinkLeavesTarget },
	{ "TestTruncatedReplacementLeavesNoDebris", TestTruncatedReplacementLeavesNoDebris },
	{ "TestResumeWellFormedRange", TestResumeWellFormedRange },
	{ "TestResumeMalformedRangeNeverCorrupts", TestResumeMalformedRangeNeverCorrupts },
	{ "TestResumeThroughSymlink", TestResumeThroughSymlink },
	{ "TestPlainDownloadReplacesSymlink", TestPlainDownloadReplacesSymlink },
	{ "TestResumeCompleteReadOnlyFile", TestResumeCompleteReadOnlyFile },
	{ "TestResumePartialReadOnlyFileFails", TestResumePartialReadOnlyFileFails },
	{ "TestResumeTargetIsTheMeasuredFile", TestResumeTargetIsTheMeasuredFile },
	{ "TestRedirectCredentialsStayInOrigin", TestRedirectCredentialsStayInOrigin },
	{ "TestRedirectCredentialsSameOrigin", TestRedirectCredentialsSameOrigin },
	{ "TestPassivePortrangeDefault", TestPassivePortrangeDefault },
	{ "TestWriteErrorIsReported", TestWriteErrorIsReported },
	{ "TestWriteErrorToStdout", TestWriteErrorToStdout },
	{ "TestAutoRetryProducesExactContent", TestAutoRetryProducesExactContent },
	{ "TestAutoRetryToStdout", TestAutoRetryToStdout },
	{ "TestAutoRetryUsesRange", TestAutoRetryUsesRange },
	{ "TestAutoRetryToDevice", TestAutoRetryToDevice },
	{ "TestRedirectToFileNotFollowed", TestRedirectToFileNotFollowed },
	{ "TestStdoutWritesNoFiles", TestStdoutWritesNoFiles },
	{ "TestOutputElsewhere", TestOutputElsewhere },
	{ "TestIfModifiedSinceFile", TestIfModifiedSinceFile },
	{ "TestResumeMtimeMismatch", TestResumeMtimeMismatch },
	{ "TestResumePreciousMismatch", TestResumePreciousMismatch },
	{ "TestReplaceKeepsModeAndLeavesNoTemp", TestReplaceKeepsModeAndLeavesNoTemp },
	{ "TestDevNullUnveilsOnlyTheDevice", TestDevNullUnveilsOnlyTheDevice },
	{ "TestSOCKS5", TestSOCKS5 },
	{ "TestSOCKS5Refused", TestSOCKS5Refused },
	{ "TestSOCKS5BadVersion", TestSOCKS5BadVersion },
	{ "TestSOCKS5FragmentedReplies", TestSOCKS5FragmentedReplies },
	{ "TestSOCKS5CoalescedReplyKeepsPayload", TestSOCKS5CoalescedReplyKeepsPayload },
	{ "TestSOCKS5ReplyAddressTypes", TestSOCKS5ReplyAddressTypes },
	{ "TestSOCKS5MalformedReply", TestSOCKS5MalformedReply },
	{ "TestSOCKS5TrickleHonoursTimeout", TestSOCKS5TrickleHonoursTimeout },
	{ "TestTLSUntrustedRejected", TestTLSUntrustedRejected },
	{ "TestTLSNoVerifyPeer", TestTLSNoVerifyPeer },
	{ "TestTLSTrustedCA", TestTLSTrustedCA },
	{ "TestTLSBinaryIntegrity", TestTLSBinaryIntegrity },
	{ "TestTLSHostnameMismatch", TestTLSHostnameMismatch },
	{ "TestTLSPlainServer", TestTLSPlainServer },
	{ "TestVerboseNeverShowsCredentials", TestVerboseNeverShowsCredentials },
	{ "TestVerboseStillAuthenticates", TestVerboseStillAuthenticates },
	{ "TestVerboseKeepsOtherHeaders", TestVerboseKeepsOtherHeaders },
	{ "TestVerboseNeverShowsNetrcOrFTPPassword", TestVerboseNeverShowsNetrcOrFTPPassword },
};
const size_t ntests = sizeof(tests) / sizeof(tests[0]);
