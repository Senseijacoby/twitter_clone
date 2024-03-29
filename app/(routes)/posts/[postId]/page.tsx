import { useSearchParams } from 'next/navigation'
import { ClipLoader } from "react-spinners";

import usePost from "@/hooks/usePost";

import Header from "@/components/Header";
import Form from "@/components/Form";
import PostItem from "@/components/posts/PostItem";
import CommentFeed from "@/components/posts/CommentFeed";
import { AnyARecord } from 'dns';


interface PostViewProps {
    data: Record<string, any>;
    postId?: Record<number, AnyARecord>;
    userId?: string;
}

const PostView: React.FC<PostViewProps> = () => {
    const searchParams = useSearchParams()
    const postId = searchParams.get(' postId ');

    const { data: fetchedPost, isLoading } = usePost(postId as string);

    if (isLoading || !fetchedPost) {
        return (
            <div className="flex justify-center items-center h-full">
                <ClipLoader color="lightblue" size={80} />
            </div>
        )
    }

    return (
        <>
            <Header showBackArrow label="Tweet" />
            <PostItem data={fetchedPost} />
            <Form postId={postId as string} isComment placeholder="Tweet your reply" />
            <CommentFeed comments={fetchedPost?.comments} />
        </>
    );
}

export default PostView;