package org.visiontech.jenkins.aws.s3.cleaner;

import com.amazonaws.regions.Regions;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagement;
import com.amazonaws.services.identitymanagement.AmazonIdentityManagementClientBuilder;
import com.amazonaws.services.identitymanagement.model.GetUserResult;
import com.amazonaws.services.s3.AmazonS3;
import com.amazonaws.services.s3.AmazonS3ClientBuilder;
import com.amazonaws.services.s3.model.ListVersionsRequest;
import com.amazonaws.services.s3.model.ObjectListing;
import com.amazonaws.services.s3.model.S3ObjectSummary;
import com.amazonaws.services.s3.model.S3VersionSummary;
import com.amazonaws.services.s3.model.VersionListing;
import com.cloudbees.jenkins.plugins.awscredentials.AWSCredentialsHelper;
import com.cloudbees.jenkins.plugins.awscredentials.AmazonWebServicesCredentials;
import com.cloudbees.plugins.credentials.CredentialsProvider;
import hudson.Launcher;
import hudson.Extension;
import hudson.FilePath;
import hudson.util.FormValidation;
import hudson.model.AbstractProject;
import hudson.model.Item;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.Builder;
import hudson.tasks.BuildStepDescriptor;
import hudson.util.ListBoxModel;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.QueryParameter;

import javax.servlet.ServletException;
import java.io.IOException;
import java.net.HttpURLConnection;
import java.util.Arrays;
import java.util.Collections;
import java.util.Objects;
import java.util.stream.Collectors;
import jenkins.tasks.SimpleBuildStep;
import org.apache.commons.collections.ListUtils;
import org.apache.commons.lang.StringUtils;
import org.jenkinsci.Symbol;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.verb.POST;

public class AWSS3CleanerBuilder extends Builder implements SimpleBuildStep {

    private final String credentialId;
    private final String awsRegion;
    private final String bucketName;

    @DataBoundConstructor
    public AWSS3CleanerBuilder(String credentialId, String awsRegion, String bucketName) {
        this.credentialId = credentialId;
        this.awsRegion = awsRegion;
        this.bucketName = bucketName;
    }

    public String getCredentialId() {
        return credentialId;
    }

    public String getAwsRegion() {
        return awsRegion;
    }

    public String getBucketName() {
        return bucketName;
    }

    @Override
    public void perform(Run<?, ?> run, FilePath workspace, Launcher launcher, TaskListener listener) throws InterruptedException, IOException {

        AmazonS3ClientBuilder builder = AmazonS3ClientBuilder.standard();
        builder.withCredentials(CredentialsProvider.findCredentialById(credentialId, AmazonWebServicesCredentials.class, run, Collections.EMPTY_LIST));
        builder.withClientConfiguration(Utils.getClientConfiguration());
        builder.withRegion(Regions.fromName(awsRegion));
        AmazonS3 s3 = builder.build();

        ObjectListing object_listing = s3.listObjects(bucketName);

        while (true) {
            for (S3ObjectSummary summary : object_listing.getObjectSummaries()) {
                s3.deleteObject(bucketName, summary.getKey());
            }
            if (object_listing.isTruncated()) {
                object_listing = s3.listNextBatchOfObjects(object_listing);
            } else {
                break;
            }
        }

        VersionListing version_listing = s3.listVersions(new ListVersionsRequest().withBucketName(bucketName));
        while (true) {
            for (S3VersionSummary vs : version_listing.getVersionSummaries()) {
                s3.deleteVersion(bucketName, vs.getKey(), vs.getVersionId());
            }
            if (version_listing.isTruncated()) {
                version_listing = s3.listNextBatchOfVersions(version_listing);
            } else {
                break;
            }
        }
        
    }

    @Symbol("awsS3Cleaner")
    @Extension
    public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {

        @POST
        public FormValidation doCheckCredentialId(@QueryParameter String value, @AncestorInPath Item owner) throws IOException, ServletException {
            owner.checkPermission(Item.CONFIGURE);            
            if (StringUtils.isBlank(value)) {
                return FormValidation.error(Messages.AWSS3CleanerBuilder_DescriptorImpl_errors_missingValue());
            }

            AmazonIdentityManagementClientBuilder builder = AmazonIdentityManagementClientBuilder.standard();
            builder.withCredentials(AWSCredentialsHelper.getCredentials(value, owner.getParent()));
            builder.withClientConfiguration(Utils.getClientConfiguration());

            AmazonIdentityManagement iam = builder.build();
            GetUserResult user = iam.getUser();

            if (Objects.isNull(user) || Objects.isNull(user.getSdkHttpMetadata()) || !Objects.equals(HttpURLConnection.HTTP_OK, user.getSdkHttpMetadata().getHttpStatusCode())) {
                return FormValidation.error(Messages.AWSS3CleanerBuilder_DescriptorImpl_errors_credentialNotFound());
            }

            return FormValidation.ok();
        }

        public FormValidation doCheckAwsRegion(@QueryParameter String value) {
            return Utils.doCheckValueIsNotBlank(value);
        }

        public FormValidation doCheckBucketName(@QueryParameter String value) {
            return Utils.doCheckValueIsNotBlank(value);
        }

        @Override
        public boolean isApplicable(Class<? extends AbstractProject> aClass) {
            return true;
        }

        @Override
        public String getDisplayName() {
            return Messages.AWSS3CleanerBuilder_DescriptorImpl_DisplayName();
        }

        public ListBoxModel doFillCredentialIdItems(@AncestorInPath Item owner) {
            if (Objects.isNull(owner) || !owner.hasPermission(Item.CONFIGURE)) {
                return new ListBoxModel(Utils.EMPTY_OPTION);
            }
            return AWSCredentialsHelper.doFillCredentialsIdItems(owner.getParent());
        }

        public ListBoxModel doFillAwsRegionItems(@AncestorInPath Item owner) {
            if (Objects.isNull(owner) || !owner.hasPermission(Item.CONFIGURE)) {
                return new ListBoxModel(Utils.EMPTY_OPTION);
            }
            return new ListBoxModel(ListUtils.union(Arrays.asList(Utils.EMPTY_OPTION), Arrays.asList(Regions.values()).stream().map(region -> new ListBoxModel.Option(region.getDescription(), region.getName())).collect(Collectors.toList())));
        }

        public ListBoxModel doFillBucketNameItems(@AncestorInPath Item owner, @QueryParameter String credentialId, @QueryParameter String awsRegion) {
            if (Objects.isNull(owner) || !owner.hasPermission(Item.CONFIGURE) || StringUtils.isBlank(credentialId) || StringUtils.isBlank(awsRegion)) {
                return new ListBoxModel(Utils.EMPTY_OPTION);
            }
            AmazonS3ClientBuilder builder = AmazonS3ClientBuilder.standard();
            builder.withCredentials(AWSCredentialsHelper.getCredentials(credentialId, owner.getParent()));
            builder.withClientConfiguration(Utils.getClientConfiguration());
            builder.withRegion(Regions.fromName(awsRegion));
            AmazonS3 s3 = builder.build();
            return new ListBoxModel(ListUtils.union(Arrays.asList(Utils.EMPTY_OPTION), s3.listBuckets().stream().map(bucket -> new ListBoxModel.Option(bucket.getName())).collect(Collectors.toList())));
        }

    }

}
